/*
 * filesrv is a single-file web server.
 * Copyright (C) 2019 Esote
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_LEN		4096
#define QUEUE_LEN	10

/* Memory-mapped file. */
static uint8_t *file;
static size_t file_l;

static int fd, sfd, afd;
static int lazy;

static void
sigint_handler(int sig, siginfo_t *info, void *ucontext)
{
	(void)sig;
	(void)info;
	(void)ucontext;

	/* Try to be polite while we're on our way out. */

	if (lazy == 0) {
		(void)munmap(file, file_l);
	} else {
		(void)close(fd);
	}

	(void)close(sfd);
	(void)close(afd);
	_exit(0);
}

static int
cat(int in, int out)
{
	static uint8_t buf[BUF_LEN];
	ssize_t r, off, w;
	w = 0;

	if (lseek(in, 0, SEEK_SET) == -1) {
		err(1, "lseek");
	}

	while ((r = read(in, buf, BUF_LEN)) > 0) {
		for (off = 0; r > 0; r -= w, off += w) {
			if ((w = write(out, buf + off, (size_t)r)) <= 0) {
				return -1;
			}
		}
	}

	if (r == -1) {
		return -1;
	}

	return 0;
}

static void
check_port(int fd)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == -1) {
		err(1, "getsockname");
	}

	(void)printf("assigned port '%u'\n", ntohs(addr.sin_port));
}

static void
map(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == -1) {
		err(1, "fstat");
	}

	if (st.st_size == 0) {
		errx(1, "empty file");
	}

	file_l = (size_t)st.st_size;
	if ((file = mmap(NULL, file_l, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
		err(1, "mmap");
	}

	if (close(fd) == -1) {
		err(1, "close fd");
	}
}

int
main(int argc, char *argv[])
{
	struct sigaction act;
	struct sockaddr_in addr;
	socklen_t addrlen;
	unsigned long n;
	int ch;
	int opt;
	char *end;
	uint16_t port;

	addrlen = sizeof(addr);
	lazy = 0;
	opt = 1;
	port = 8080;

	while ((ch = getopt(argc, argv, "lp:")) != -1) {
		switch (ch) {
		case 'l':
			lazy = 1;
			break;
		case 'p':
			n = strtoul(optarg, &end, 0);

			if (errno == EINVAL || errno == ERANGE) {
				err(1, "port string invalid");
			} else if (optarg == end) {
				err(1, "no port string read");
			} else if (n > UINT16_MAX) {
				warnx("port number '%lu' will overflow", n);
			}

			port = (uint16_t)n;
			break;
		default:
			(void)fprintf(stderr, "usage: %s [-l] [-p port] file\n",
				argv[0]);
			return 1;
		}
	}

	argc -= optind;
	if (argc == 0) {
		(void)fprintf(stderr, "usage: %s [-l] [-p port] file\n",
			argv[0]);
		return 1;
	}

	argv += optind;
	if ((fd = open(argv[0], O_RDONLY)) == -1) {
		err(1, "open");
	}

	if (lazy == 0) {
		map(fd);
	}

	if (geteuid() == 0) {
		if (chroot(".") == -1) {
			err(1, "chroot");
		}
	}

#ifdef __OpenBSD__
	if (pledge("stdio inet", "") == -1) {
		err(1, "pledge");
	}
#endif

	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		err(1, "socket");
	}

	(void)memset(&act, 0, sizeof(act));

	if (sigemptyset(&act.sa_mask) == -1) {
		err(1, "sigemptyset");
	}

	act.sa_sigaction = sigint_handler;

	if (sigaction(SIGINT, &act, NULL) == -1) {
		err(1, "sigaction");
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		err(1, "setsockopt SO_REUSEADDR");
	}

	(void)memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		err(1, "bind");
	}

	if (port == 0) {
		check_port(sfd);
	}

	if (listen(sfd, QUEUE_LEN) == -1) {
		err(1, "listen");
	}

	while (1) {
		if ((afd = accept(sfd, (struct sockaddr *)&addr, &addrlen)) == -1) {
			warn("accept");
			continue;
		}

		/* Dear prospective client, please shut up already. */
		if (shutdown(afd, SHUT_RD) == -1) {
			warn("shutdown rd");
			goto done;
		}

		if (lazy == 0) {
			if (write(afd, file, file_l) == -1) {
				warn("write mmap");
				goto done;
			}
		} else {
			if (cat(fd, afd) == -1) {
				warn("cat");
				goto done;
			}
		}

		if (shutdown(afd, SHUT_RDWR) == -1) {
			warn("shutdown rdwr");
		}
done:
		if (close(afd) == -1) {
			warn("close afd");
		}
	}
}
