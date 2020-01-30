/*
 * filesrv is a filesystem web server.
 * Copyright (C) 2020 Esote
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

#ifndef __OpenBSD__
#define _GNU_SOURCE /* setresgid, setresuid */
#endif

#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filesrv.h"

#define PORT_DEFAULT	8080
#define Q_LEN		20
#define T_DEFAULT	3
#define USAGE		"usage: %s [-d] [-p port] [-t timeout] [-u user] dir\n"

static uint16_t	assigned_port(int);
static void	mkdaemon(int);

int
main(int argc, char *argv[])
{
	char dir[PATH_MAX];
	struct sockaddr_in addr;
	struct sigaction act;
	struct timeval tv;
	struct passwd *pw;
	size_t dirlen;
	socklen_t addrlen;
	unsigned long n;
	int afd, sfd;
	int ch;
	int daemonize;
	int opt;
	char *end;
	char *user;
	uint16_t port;

	tv.tv_sec = T_DEFAULT;
	tv.tv_usec = 0;

	addrlen = sizeof(addr);

	sfd = -1;
	afd = -1;

	opt = 1;

	daemonize = 0;
	user = NULL;
	port = PORT_DEFAULT;

	while ((ch = getopt(argc, argv, "dp:t:u:")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = 1;
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
		case 't':
			tv.tv_sec = (time_t)strtoul(optarg, &end, 0);

			if (errno == EINVAL || errno == ERANGE) {
				err(1, "timeout string invalid");
			} else if (optarg == end) {
				err(1, "no timeout string read");
			}

			break;
		case 'u':
			user = optarg;
			break;
		default:
			(void)fprintf(stderr, USAGE, argv[0]);
			return 1;
		}
	}

	argc -= optind;

	if (argc == 0) {
		(void)fprintf(stderr, "No directory specified\n" USAGE,
			argv[0]);
		return 1;
	}

	argv += optind;

	if (getuid() == 0) {
		if (user != NULL) {
			if ((pw = getpwnam(user)) == NULL) {
				err(1, "privdrop: getpwnam");
			}
		}

		if (chroot(argv[0]) == -1) {
			err(1, "chroot");
		}

		if (chdir("/") == -1) {
			err(1, "chdir");
		}
	} else {
		if (user != NULL) {
			errx(1, "privdrop is restricted to uid 0");
		}

		if (chdir(argv[0]) == -1) {
			err(1, "chdir");
		}
	}


	if (getcwd(dir, PATH_MAX) == NULL) {
		err(1, "getcwd");
	}

	dirlen = strnlen(dir, PATH_MAX);

	(void)memset(&act, 0, sizeof(act));

	if (sigemptyset(&act.sa_mask) == -1) {
		err(1, "sigemptyset");
	}

	act.sa_handler = SIG_IGN;

	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		err(1, "sigaction SIGPIPE");
	}

	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		err(1, "socket");
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
		(void)printf("assigned port %u\n", assigned_port(sfd));
	}

	if (listen(sfd, Q_LEN) == -1) {
		err(1, "listen");
	}

	/* Drop privileges. */
	if (user != NULL) {
		if (setgroups(1, &pw->pw_gid) == -1) {
			err(1, "privdrop: setgroups");
		}

		if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
			err(1, "privdrop: setresgid");
		}

		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			err(1, "privdrop: setresuid");
		}
	}

#ifdef __OpenBSD__
	if (unveil(".", "r") == -1) {
		err(1, "unveil");
	}
#endif

	if (daemonize == 1) {
		mkdaemon(sfd);
	}

#ifdef __OpenBSD__
	if (pledge("stdio rpath inet", "") == -1) {
		err(1, "pledge");
	}
#endif

	while (1) {
		if ((afd = accept(sfd, (struct sockaddr *)&addr, &addrlen)) == -1) {
			warn("accept");
			continue;
		}

		if (setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
			warn("setsockopt SO_RCVTIMEO");
			goto done;
		}

		if (setsockopt(afd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
			warn("setsockopt SO_SNDTIMEO");
			goto done;
		}

		respond(afd, dir, dirlen);
		errno = 0;

		if (shutdown(afd, SHUT_RDWR) == -1 && errno != ENOTCONN) {
			warn("shutdown rdwr");
		}

done:
		if (close(afd) == -1) {
			warn("close afd");
		}
	}
}

static uint16_t
assigned_port(int fd)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == -1) {
		err(1, "getsockname");
	}

	return ntohs(addr.sin_port);
}

static void
mkdaemon(int sfd)
{
	long i;
	pid_t p;

	if ((p = fork()) == -1) {
		err(1, "daemon first fork");
	} else if (p > 0) {
		exit(0);
	}

	if (setsid() == -1) {
		err(1, "setsid");
	}

	if ((p = fork()) == -1) {
		err(1, "daemon second fork");
	} else if (p > 0) {
		printf("daemon pid %d\n", p);
		exit(0);
	}

	(void)umask(0);

	if (chdir("/") == -1) {
		err(1, "chdir");
	}

	if ((i = sysconf(_SC_OPEN_MAX)) == -1) {
		err(1, "sysconf _SC_OPEN_MAX");
	} else if (i > INT_MAX) {
		i = INT_MAX;
		warnx("_SC_OPEN_MAX exceeds max fd value");
	}

	for (; i >= 0; --i) {
		if (i != sfd && close((int)i) == -1 && errno != EBADF
			&& i >= STDERR_FILENO) {
			warn("closing fd %ld failed", i);
		}
	}

	errno = 0;
}
