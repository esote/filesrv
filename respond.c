#include <sys/socket.h>
#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filesrv.h"

#define BUF_LEN	8192

#if BUF_LEN < PATH_MAX
#error BUF_LEN too small
#endif

#define NL	"\r\n"
#define SP	" \t\v\f"

#define TIMEOUT(X)	((X) == EAGAIN || (X) == EWOULDBLOCK || (X) == EINPROGRESS)
#define DOT(X)		(strcmp((X), ".") == 0 || strcmp((X), "..") == 0)

static void	writefile(int, char *, off_t);
static void	writedir(int, char *);
static int	cat(int, int);
static void	status(int, char *);

#define HTTP_400	"400 Bad Request"
#define HTTP_403	"403 Forbidden"
#define HTTP_404	"404 Not Found"
#define HTTP_405	"405 Method Not Allowed"
#define HTTP_408	"408 Request Timeout"

static char rbuf[BUF_LEN]; /* read buffer, path buffer */
static char wbuf[BUF_LEN]; /* response buffer, path swap buffer */

void
respond(int afd, char *dir, size_t dirlen)
{
	struct stat st;
	size_t len;
	ssize_t n;
	char *line, *word, *lline, *lword;
	char *path;

	if ((n = read(afd, rbuf, BUF_LEN-1)) == -1) {
		if (TIMEOUT(errno)) {
			status(afd, HTTP_408);
		} else {
			warn("read");
		}
		return;
	}

	rbuf[n] = '\0';

	if (shutdown(afd, SHUT_RD) == -1) {
		if (errno != ENOTCONN) {
			warn("shutdown rd");
		}
		return;
	}

	if ((line = strtok_r(rbuf, NL, &lline)) == NULL) {
		status(afd, HTTP_400);
		return;
	}

	if ((word = strtok_r(line, SP, &lword)) == NULL) {
		status(afd, HTTP_400);
		return;
	}

	if (strcmp(word, "GET") != 0) {
		status(afd, HTTP_405);
		return;
	}

	if ((path = strtok_r(NULL, SP NL, &lword)) == NULL) {
		status(afd, HTTP_400);
		return;
	}

	if (dirlen != 0 && dir[dirlen-1] == '/') {
		path++;
	}

	len = strlen(path);
	if (len + dirlen + 1 > BUF_LEN) {
		/* ENAMETOOLONG */
		status(afd, HTTP_404);
		return;
	}

	(void)memcpy(wbuf, dir, dirlen);
	(void)memcpy(wbuf + dirlen, path, len+1);

	if ((path = realpath(wbuf, rbuf)) == NULL) {
		switch (errno) {
		case EACCES:
			status(afd, HTTP_403);
			break;
		case ENOENT:
			status(afd, HTTP_404);
			break;
		default:
			status(afd, HTTP_400);
		}
		return;
	}

	if (memcmp(dir, path, dirlen) != 0) {
		/* Path escapes sandbox. */
		status(afd, HTTP_404);
		return;
	}

	if (stat(path, &st) == -1) {
		switch (errno) {
		case EACCES:
			status(afd, HTTP_403);
			break;
		case ENOENT:
			status(afd, HTTP_404);
			break;
		default:
			status(afd, HTTP_400);
		}
		return;
	}

	if (S_ISREG(st.st_mode)) {
		writefile(afd, path, st.st_size);
	} else if (S_ISDIR(st.st_mode)) {
		writedir(afd, path);
	} else {
		status(afd, HTTP_404);
	}
}

static void
writefile(int afd, char *path, off_t size)
{
	ssize_t n;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		switch (errno) {
		case EACCES:
			status(afd, HTTP_403);
			break;
		case ENOENT:
			status(afd, HTTP_404);
			break;
		default:
			status(afd, HTTP_400);
		}
		return;
	}

	n = snprintf(wbuf, BUF_LEN, "HTTP/1.1 200 OK\r\n"
		"Content-Length: %zd\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"\r\n", (ssize_t)size);

	if (n < 0) {
		warnx("snprintf");
		goto done;
	}

	if (write(afd, wbuf, (size_t)n) == -1) {
		goto done;
	}

	if (cat(fd, afd) == -1) {
		if (!TIMEOUT(errno)) {
			warn("cat");
		}
	}

done:
	if (close(fd) == -1) {
		warn("close file");
	}
}

static void
writedir(int afd, char *path)
{
	DIR *dir;
	struct dirent *d;
	size_t size;
	size_t tmp;
	ssize_t n;

	if ((dir = opendir(path)) == NULL) {
		switch (errno) {
		case EACCES:
			status(afd, HTTP_403);
			break;
		case ENOENT:
			status(afd, HTTP_404);
			break;
		default:
			status(afd, HTTP_400);
		}
		return;
	}

#define PRE_1	"<pre>\n"
#define PRE_2	"</pre>\n"
#define LINK_1	"<a href=\"./"
#define LINK_2	"\">"
#define LINK_3	"</a>\n"

	size = sizeof(PRE_1) + sizeof(PRE_2) - 2;

	/* Calculate Content-Length. */
	errno = 0;
	while ((d = readdir(dir)) != NULL) {
		if (DOT(d->d_name)) {
			continue;
		}

		tmp = 2 * strlen(d->d_name)
			+ sizeof(LINK_1) - 1
			+ sizeof(LINK_2) - 1
			+ sizeof(LINK_3) - 1;

		if (d->d_type == DT_DIR) {
			tmp += 2;
		}

		if (size + tmp < size) {
			warnx("writedir size overflow");
			goto done;
		}

		size += tmp;
	}

	if (errno != 0) {
		if (errno == ENOENT) {
			status(afd, HTTP_404);
		} else {
			warn("readddir first");
		}
		goto done;
	}

	rewinddir(dir);

	n = snprintf(wbuf, BUF_LEN, "HTTP/1.1 200 OK\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"\r\n", size);

	if (n < 0) {
		warnx("snprintf");
		goto done;
	}

	if (write(afd, wbuf, (size_t)n) == -1) {
		goto done;
	}

	if (write(afd, PRE_1, sizeof(PRE_1) - 1) == -1) {
		goto done;
	}

	errno = 0;
	while ((d = readdir(dir)) != NULL) {
		if (DOT(d->d_name)) {
			continue;
		}

		tmp = strlen(d->d_name);

		/* Write link to file or directory. */
		if (write(afd, LINK_1, sizeof(LINK_1) - 1) == -1
			|| write(afd, d->d_name, tmp) == -1
			|| (d->d_type == DT_DIR && write(afd, "/", 1) == -1)
			|| write(afd, LINK_2, sizeof(LINK_2) - 1) == -1
			|| write(afd, d->d_name, tmp) == -1
			|| (d->d_type == DT_DIR && write(afd, "/", 1) == -1)
			|| write(afd, LINK_3, sizeof(LINK_3) - 1) == -1) {
			goto done;
		}
	}

	if (errno != 0) {
		if (errno != ENOENT) {
			warn("readdir second");
		}
		goto done;
	}

	if (write(afd, PRE_2, sizeof(PRE_2) - 1) == -1) {
		goto done;
	}

done:
	if (closedir(dir) == -1) {
		warn("close dir");
	}
}

static int
cat(int in, int out)
{
	ssize_t r, off, w;
	w = 0;

	while ((r = read(in, wbuf, BUF_LEN)) > 0) {
		for (off = 0; r > 0; r -= w, off += w) {
			if ((w = write(out, wbuf + off, (size_t)r)) <= 0) {
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
status(int fd, char *code)
{
	int n = snprintf(wbuf, BUF_LEN, "HTTP/1.1 %s\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"\r\n"
		"%s\n", code, strlen(code)+1, code);

	if (n < 0) {
		warnx("snprintf");
		return;
	}

	/* Don't care if it fails. */
	(void)write(fd, wbuf, (size_t)n);
}
