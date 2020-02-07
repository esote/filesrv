/* MIME sniffing implementation based on Go's http.DetectContentType() and
 * mime.TypeByExtension(). */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ISWS(X)	((X) == '\t' || (X) == '\n' || (X) == '\x0c' || (X) == '\r' || (X) == ' ')
#define ISTT(X)	((X) == ' ' || (X) == '>')

struct ext_map {
	char *ext;
	char *mime;
};

static struct ext_map ext_map[] = {
	{ ".css", "text/css; charset=utf-8" },
	{ ".gif", "image/gif" },
	{ ".htm", "text/html; charset=utf-8" },
	{ ".html", "text/html; charset=utf-8" },
	{ ".jpeg", "image/jpeg" },
	{ ".jpg", "image/jpeg" },
	{ ".js", "application/javascript" },
	{ ".mjs", "application/javascript" },
	{ ".pdf", "application/pdf" },
	{ ".png", "image/png" },
	{ ".svg", "image/svg+xml" },
	{ ".wasm", "application/wasm" },
	{ ".webp", "image/webp" },
	{ ".xml", "text/xml; charset=utf-8" },
	{ NULL, NULL }
};

union arg {
	struct html {
		size_t siglen;
		char *sig;
	} html;
	struct masked {
		int skipWS;
		size_t masklen;
		char *mask;
		char *pattern;
		char *mime;
	} masked;
	struct exact {
		size_t siglen;
		char *sig;
		char *mime;
	} exact;
};

struct sig {
	char *(*match) (uint8_t *, size_t, size_t, union arg *);
	union arg arg;
};

static char *	exact(uint8_t *, size_t, size_t, union arg *);
static char *	html(uint8_t *, size_t, size_t, union arg *);
static char *	masked(uint8_t *, size_t, size_t, union arg *);
static char *	mp4(uint8_t *, size_t, size_t, union arg *);
static char *	text(uint8_t *, size_t, size_t, union arg *);

static char *	sniff_ext(char *);
static char *	ext(char *);

static struct sig sigs[] = {
	{
		html, { .html = {14, "<!DOCTYPE HTML"}}
	},
	{
		html, { .html = {5, "<HTML"}}
	},
	{
		html, { .html = {5, "<HEAD"}}
	},
	{
		html, { .html = {7, "<SCRIPT"}}
	},
	{
		html, { .html = {7, "<IFRAME"}}
	},
	{
		html, { .html = {3, "<H1"}}
	},
	{
		html, { .html = {4, "<DIV"}}
	},
	{
		html, { .html = {5, "<FONT"}}
	},
	{
		html, { .html = {6, "<TABLE"}}
	},
	{
		html, { .html = {3, "<A"}}
	},
	{
		html, { .html = {6, "<STYLE"}}
	},
	{
		html, { .html = {6, "<TITLE"}}
	},
	{
		html, { .html = {3, "<B"}}
	},
	{
		html, { .html = {5, "<BODY"}}
	},
	{
		html, { .html = {3, "<BR"}}
	},
	{
		html, { .html = {3, "<P"}}
	},
	{
		html, { .html = {4, "<!--"}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 1,
			.masklen = 5,
			.mask = "\xFF\xFF\xFF\xFF\xFF",
			.pattern = "<?xml",
			.mime = "text/xml; charset=utf-8"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 5,
			.sig = "%PDF-",
			.mime = "application/pdf"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 11,
			.sig = "%!PS-Adobe-",
			.mime = "application/postscript"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 4,
			.mask = "\xFF\xFF\x00\x00",
			.pattern = "\xFE\xFF\x00\x00",
			.mime = "text/plain; charset=utf-16be"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 4,
			.mask = "\xFF\xFF\x00\x00",
			.pattern = "\xFF\xFE\x00\x00",
			.mime = "text/plain; charset=utf-16le"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 4,
			.mask = "\xFF\xFF\xFF\x00",
			.pattern = "\xEF\xBB\xBF\x00",
			.mime = "text/plain; charset=utf-8"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "\x00\x00\x01\x00",
			.mime = "image/x-icon"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "\x00\x00\x02\x00",
			.mime = "image/x-icon"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 2,
			.sig = "BM",
			.mime = "image/bmp"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 6,
			.sig = "GIF87a",
			.mime = "image/gif"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 6,
			.sig = "GIF89a",
			.mime = "image/gif"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 14,
			.mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
			.pattern = "RIFF\x00\x00\x00\x00WEBPVP",
			.mime = "image/webp"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 8,
			.sig = "\x89PNG\x0D\x0A\x1A\x0A",
			.mime = "image/png"
		}},
	},
	{
		exact,
		{ .exact = {
			.siglen = 3,
			.sig = "\xFF\xD8\xFF",
			.mime = "image/jpeg"
		}},
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 4,
			.mask = "\xFF\xFF\xFF\xFF",
			.pattern = ".snd",
			.mime = "audio/basic"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 12,
			.mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			.pattern = "FORM\x00\x00\x00\x00AIFF",
			.mime = "audio/aiff"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 3,
			.mask = "\xFF\xFF\xFF",
			.pattern = "ID3",
			.mime = "audio/mpeg"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 5,
			.mask = "\xFF\xFF\xFF\xFF\xFF",
			.pattern = "OggS\x00",
			.mime = "application/ogg"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 8,
			.mask = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pattern = "MThd\x00\x00\x00\x06",
			.mime = "audio/midi"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 12,
			.mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			.pattern = "RIFF\x00\x00\x00\x00AVI ",
			.mime = "video/avi"
		}}
	},
	{
		masked,
		{ .masked = {
			.skipWS = 0,
			.masklen = 12,
			.mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
			.pattern = "RIFF\x00\x00\x00\x00WAVE",
			.mime = "audio/wave"
		}}
	},
	{ mp4, {} },
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "\x1A\x45\xDF\xA3",
			.mime = "video/webm"
		}},
	},
	{
		masked,
		{.masked = {
			.skipWS = 0,
			.masklen = 36,
			.mask = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
			.pattern = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
			.mime = "application/vnd.ms-fontobject"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "\x00\x01\x00\x00",
			.mime = "font/ttf"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "OTTO",
			.mime = "font/otf"
		}}
	},
	{
		exact,
		{ .exact = {
			.sig = "ttcf",
			.siglen = 4,
			.mime = "font/collection"
		}}
	},
	{
		exact,
		{ .exact = {
			.sig = "wOFF",
			.siglen = 4,
			.mime = "font/woff"
		}}
	},
	{
		exact,
		{ .exact = {
			.sig = "wOF2",
			.siglen = 4,
			.mime = "font/woff2"
		}}
	},
	{
		exact,
		{ .exact = {
			.sig = "\x1F\x8B\x08",
			.siglen = 3,
			.mime = "application/x-gzip"
		}}
	},
	{
		exact,
		{ .exact = {
			.sig = "PK\x03\x04",
			.siglen = 4,
			.mime = "application/zip"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 7,
			.sig = "Rar!\x1A\x07\x00",
			.mime = "application/x-rar-compressed"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 8,
			.sig = "Rar!\x1A\x07\x01\x00",
			.mime = "application/x-rar-compressed"
		}}
	},
	{
		exact,
		{ .exact = {
			.siglen = 4,
			.sig = "\x00\x61\x73\x6D",
			.mime = "application/wasm"
		}}
	},
	{ text, {} },
	{ NULL, {} }
};

char *
sniff(int fd, char *path)
{
	uint8_t buf[512];
	size_t nonws;
	ssize_t len;
	ssize_t i;
	char *mime;

	if ((mime = sniff_ext(path)) != NULL) {
		return mime;
	}

	if ((len = read(fd, buf, 512)) == -1) {
		goto err;
	}

	for (i = 0; i < len && ISWS(buf[i]); i++) {
	}

	nonws = (size_t)i;

	for (i = 0; sigs[i].match != NULL; i++) {
		if ((mime = sigs[i].match(buf, (size_t)len, nonws, &sigs[i].arg)) != NULL) {
			goto done;
		}
	}

err:
	mime = "application/octet-stream";

done:
	(void)lseek(fd, 0, SEEK_SET);
	return mime;
}

static char *
sniff_ext(char *path)
{
	size_t i;
	if ((path = ext(path)) == NULL) {
		return NULL;
	}

	for (i = 0; ext_map[i].ext != NULL; i++) {
		if (strcmp(ext_map[i].ext, path) == 0) {
			return ext_map[i].mime;
		}
	}

	return NULL;
}

static char *
ext(char *path)
{
	int i;

	for (i = (int)strlen(path) - 1; i >= 0 && path[i] != '/'; i--) {
		if (path[i] == '.') {
			return path + i;
		}
	}

	return NULL;
}

static char *
exact(uint8_t *data, size_t len, size_t nonws, union arg *arg)
{
	(void)nonws;

	if (len < arg->exact.siglen) {
		return NULL;
	}

	if (memcmp(data, arg->exact.sig, arg->exact.siglen) == 0) {
		return arg->exact.mime;
	}

	return NULL;
}

static char *
html(uint8_t *data, size_t len, size_t nonws, union arg *arg)
{
	size_t i;
	uint8_t b;

	data += nonws;
	len -= nonws;

	if (len < arg->html.siglen+1) {
		return NULL;
	}

	for (i = 0; i < arg->html.siglen; i++) {
		b = data[i];

		if ('A' <= b && b <= 'Z') {
			b = (uint8_t)(b & 0xDF);
		}

		if (arg->html.sig[1] != b) {
			return NULL;
		}
	}

	if (!ISTT(data[arg->html.siglen])) {
		return NULL;
	}

	return "text/html; charset=utf-8";
}

static char *
masked(uint8_t *data, size_t len, size_t nonWS, union arg *arg)
{
	size_t i;

	if (arg->masked.skipWS) {
		data += nonWS;
		len -= nonWS;
	}

	if (len < arg->masked.masklen) {
		return NULL;
	}

	for (i = 0; i < arg->masked.masklen; i++) {
		if ((data[i] & arg->masked.mask[i]) != arg->masked.pattern[i]) {
			return NULL;
		}
	}

	return arg->masked.mime;
}

static char *
mp4(uint8_t *data, size_t len, size_t nonws, union arg *argv)
{
	size_t i;
	uint32_t boxSize;

	(void)nonws;
	(void)argv;

	if (len < 12) {
		return NULL;
	}

	boxSize = (uint32_t)data[0] << 24
		| (uint32_t)data[1] << 16
		| (uint32_t)data[2] << 8
		| (uint32_t)data[3];

	if (len < boxSize || boxSize % 4 != 0) {
		return NULL;
	}

	if (memcmp(data + 4, "ftyp", 4) != 0) {
		return NULL;
	}

	for (i = 8; i < boxSize; i += 4) {
		if (i == 12) {
			continue;
		}

		if (memcmp(data + i, "mp4", 3) == 0) {
			return "video/mp4";
		}
	}

	return NULL;
}

static char *
text(uint8_t *data, size_t len, size_t nonws, union arg *argv)
{
	size_t i;
	(void)argv;

	data += nonws;
	len -= nonws;

	for (i = 0; i < len; i++) {
		if (data[i] <= 0x08 || data[i] == 0x0B
			|| (0x0E <= data[i] && data[i] <= 0x1A)
			|| (0x1C <= data[i] && data[i] <= 0x1F)) {
			return NULL;
		}
	}

	return "text/plain; charset=utf-8";
}
