/* MIME sniffing implementation based on Go's http.DetectContentType() and
 * mime.TypeByExtension(). */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

union ds {
	void *d;
	size_t s;
};

#define LARGEST	5

struct sig {
	char *(*match) (uint8_t *, size_t, size_t, union ds *);
	union ds argv[LARGEST];
};

static char *	exact(uint8_t *, size_t, size_t, union ds *);
static char *	html(uint8_t *, size_t, size_t, union ds *);
static char *	masked(uint8_t *, size_t, size_t, union ds *);
static char *	mp4(uint8_t *, size_t, size_t, union ds *);
static char *	text(uint8_t *, size_t, size_t, union ds *);

static char *	sniff_ext(char *);
static char *	ext(char *);

static struct sig sigs[] = {
	{ html, {{"<!DOCTYPE HTML"}, {.s = 14}} },
	{ html, {{"<HTML"}, {.s = 5}} },
	{ html, {{"<HEAD"}, {.s = 5}} },
	{ html, {{"<SCRIPT"}, {.s = 7}} },
	{ html, {{"<IFRAME"}, {.s = 7}} },
	{ html, {{"<H1"}, {.s = 3}} },
	{ html, {{"<DIV"}, {.s = 4}} },
	{ html, {{"<FONT"}, {.s = 5}} },
	{ html, {{"<TABLE"}, {.s = 6}} },
	{ html, {{"<A"}, {.s = 3}} },
	{ html, {{"<STYLE"}, {.s = 6}} },
	{ html, {{"<TITLE"}, {.s = 6}} },
	{ html, {{"<B"}, {.s = 3}} },
	{ html, {{"<BODY"}, {.s = 5}} },
	{ html, {{"<BR"}, {.s = 3}} },
	{ html, {{"<P"}, {.s = 3}} },
	{ html, {{"<!--"}, {.s = 4}} },
	{
		masked,
		{
			{.s = 1},
			{"\xFF\xFF\xFF\xFF\xFF"},
			{.s = 5},
			{"<?xml"},
			{"text/xml; charset=utf-8"}
		}
	},
	{ exact, {{"%PDF-"}, {.s = 5}, {"application/pdf"}} },
	{ exact, {{"%!PS-Adobe-"}, {.s = 11}, {"application/postscript"}} },
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\x00\x00"},
			{.s = 4},
			{"\xFE\xFF\x00\x00"},
			{"text/plain; charset=utf-16be"}}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\x00\x00"},
			{.s = 4},
			{"\xFF\xFE\x00\x00"},
			{"text/plain; charset=utf-16le"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\x00"},
			{.s = 4},
			{"\xEF\xBB\xBF\x00"},
			{"text/plain; charset=utf-8"}
		}
	},
	{ exact, {{"\x00\x00\x01\x00"}, {.s = 4}, {"image/x-icon"}} },
	{ exact, {{"\x00\x00\x02\x00"}, {.s = 4}, {"image/x-icon"}} },
	{ exact, {{"BM"}, {.s = 2}, {"image/bmp"}} },
	{ exact, {{"GIF87a"}, {.s = 6}, {"image/gif"}} },
	{ exact, {{"GIF89a"}, {.s = 6}, {"image/gif"}} },
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF"},
			{.s = 14},
			{"RIFF\x00\x00\x00\x00WEBPVP"},
			{"image/webp"}
		}
	},
	{ exact, {{"\x89PNG\x0D\x0A\x1A\x0A"}, {.s = 8}, {"image/png"}} },
	{ exact, {{"\xFF\xD8\xFF"}, {.s = 3}, {"image/jpeg"}} },
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF"},
			{.s = 4},
			{".snd"},
			{"audio/basic"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"},
			{.s = 12},
			{"FORM\x00\x00\x00\x00AIFF"},
			{"audio/aiff"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF"},
			{.s = 3},
			{"ID3"},
			{"audio/mpeg"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\xFF"},
			{.s = 5},
			{"OggS\x00"},
			{"application/ogg"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
			{.s = 8},
			{"MThd\x00\x00\x00\x06"},
			{"audio/midi"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"},
			{.s = 12},
			{"RIFF\x00\x00\x00\x00AVI "},
			{"video/avi"}
		}
	},
	{
		masked,
		{
			{.s = 0},
			{"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"},
			{.s = 12},
			{"RIFF\x00\x00\x00\x00WAVE"},
			{"audio/wave"}
		}
	},
	{ mp4, {} },
	{ exact, {{"\x1A\x45\xDF\xA3"}, {.s = 4}, {"video/webm"}} },
	{
		masked,
		{
			{.s = 0},
			{"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF"},
			{.s = 36},
			{"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP"},
			{"application/vnd.ms-fontobject"}
		}
	},
	{ exact, {{"\x00\x01\x00\x00"}, {.s = 4}, {"font/ttf"}} },
	{ exact, {{"OTTO"}, {.s = 4}, {"font/otf"}} },
	{ exact, {{"ttcf"}, {.s = 4}, {"font/collection"}} },
	{ exact, {{"wOFF"}, {.s = 4}, {"font/woff"}} },
	{ exact, {{"wOF2"}, {.s = 4}, {"font/woff2"}} },
	{ exact, {{"\x1F\x8B\x08"}, {.s = 3}, {"application/x-gzip"}} },
	{ exact, {{"PK\x03\x04"}, {.s = 4}, {"application/zip"}} },
	{
		exact,
		{
			{"Rar!\x1A\x07\x00"},
			{.s = 7},
			{"application/x-rar-compressed"}
		}
	},
	{
		exact,
		{
			{"Rar!\x1A\x07\x01\x00"},
			{.s = 8},
			{"application/x-rar-compressed"}
		}
	},
	{ exact, {{"\x00\x61\x73\x6D"}, {.s = 4}, {"application/wasm"}} },
	{ text, {} },
	{ NULL }
};

#define ISWS(X)	((X) == '\t' || (X) == '\n' || (X) == '\x0c' || (X) == '\r' || (X) == ' ')
#define ISTT(X)	((X) == ' ' || (X) == '>')

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
		if ((mime = sigs[i].match(buf, (size_t)len, nonws, sigs[i].argv)) != NULL) {
			goto done;
		}
	}

err:
	mime = "application/octet-stream";

done:
	(void)lseek(fd, 0, SEEK_SET);
	return mime;
}

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

/* argv[0] = exact signature
 * argv[1] = signature length
 * argv[2] = mime
 */
static char *
exact(uint8_t *data, size_t len, size_t nonws, union ds *argv)
{
	(void)nonws;

	if (len < argv[1].s) {
		return NULL;
	}

	if (memcmp(data, argv[0].d, argv[1].s) == 0) {
		return argv[2].d;
	}

	return NULL;
}

/* argv[0] = HTML signature
 * argv[1] = signature length
 */
static char *
html(uint8_t *data, size_t len, size_t nonws, union ds *argv)
{
	size_t i;
	uint8_t b;

	data += nonws;
	len -= nonws;

	if (len < argv[1].s+1) {
		return NULL;
	}

	for (i = 0; i < argv[1].s; i++) {
		b = data[i];

		if ('A' <= b && b <= 'Z') {
			b = (uint8_t)(b & 0xDF);
		}

		if (((uint8_t *)argv[0].d)[i] != b) {
			return NULL;
		}
	}

	if (!ISTT(data[argv[1].s])) {
		return NULL;
	}

	return "text/html; charset=utf-8";
}

/* argv[0] = skip WS
 * argv[1] = mask
 * argv[2] = mask length
 * argv[3] = pattern
 * argv[4] = mime
 */
static char *
masked(uint8_t *data, size_t len, size_t nonWS, union ds *argv)
{
	size_t i;

	if (argv[0].s) {
		data += nonWS;
		len -= nonWS;
	}

	if (len < argv[2].s) {
		return NULL;
	}

	for (i = 0; i < argv[2].s; i++) {
		if ((data[i] & ((uint8_t *)argv[1].d)[i]) != ((uint8_t *)argv[3].d)[i]) {
			return NULL;
		}
	}

	return argv[5].d;
}

static char *
mp4(uint8_t *data, size_t len, size_t nonws, union ds *argv)
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
text(uint8_t *data, size_t len, size_t nonws, union ds *argv)
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
