/* Channel input stack (tclIO.c: Tcl_Gets, Tcl_GetsObj, Tcl_Read, Tcl_ReadChars, Tcl_Seek, Tcl_Tell,
 * buffering, -encoding / -translation / -eofchar / -profile / -buffersize, CRLF and auto translation
 * across buffer boundaries). The channel is created with the exported Tcl_CreateChannel over an
 * in-memory driver whose inputProc serves the fuzz bytes in small pieces, so multi-byte sequences and
 * CR LF pairs split across reads. Input layout:
 *   byte 0   encoding index                       byte 1  translation index | eofchar index << 3
 *   byte 2   buffer size (bits 0-3) | profile (bits 4-5) | seekable (bit 6)
 *   byte 3   bits 0-4: chunk size selector, bits 5-7: unused
 *   byte 4   number of operations (1..32)         next n bytes: operations (see run_op)
 *   rest     the channel's content */
#include "fuzz_common.h"
#include <errno.h>

typedef struct {
    const uint8_t *data;
    size_t size, pos, chunk;
} Mem;

static int memInput(void *instanceData, char *buf, int toRead, int *errorCodePtr) {
    Mem *m = instanceData;
    size_t n;
    (void)errorCodePtr;
    if (m->pos >= m->size) return 0;
    n = m->size - m->pos;
    if (n > (size_t)toRead) n = (size_t)toRead;
    if (n > m->chunk) n = m->chunk;
    memcpy(buf, m->data + m->pos, n);
    m->pos += n;
    return (int)n;
}

static long long memSeek(void *instanceData, long long offset, int mode, int *errorCodePtr) {
    Mem *m = instanceData;
    long long base = mode == SEEK_SET ? 0 : mode == SEEK_CUR ? (long long)m->pos : (long long)m->size;
    if (base + offset < 0) {
        *errorCodePtr = EINVAL;
        return -1;
    }
    m->pos = (size_t)(base + offset);
    return base + offset;
}

static int memClose(void *instanceData, Tcl_Interp *interp, int flags) {
    (void)interp;
    /* Tcl first closes the read side alone (TCL_CLOSE_READ), then the whole channel (flags 0). */
    if (flags & (TCL_CLOSE_READ | TCL_CLOSE_WRITE)) return 0;
    free(instanceData);
    return 0;
}

static void memWatch(void *instanceData, int mask) {
    (void)instanceData; (void)mask;
}

static const Tcl_ChannelType seekableType = {
    "fuzzmem", TCL_CHANNEL_VERSION_5, NULL, memInput, NULL, NULL, NULL, NULL, memWatch, NULL,
    memClose, NULL, NULL, NULL, memSeek, NULL, NULL,
};
static const Tcl_ChannelType streamType = {
    "fuzzstream", TCL_CHANNEL_VERSION_5, NULL, memInput, NULL, NULL, NULL, NULL, memWatch, NULL,
    memClose, NULL, NULL, NULL, NULL, NULL, NULL,
};

static const char *const encs[] = {
    "utf-8", "iso8859-1", "utf-16", "utf-16le", "utf-16be", "utf-32", "utf-32le", "utf-32be",
    "cesu-8", "ascii", "shiftjis", "euc-jp", "iso2022-jp", "iso2022-kr", "gb2312", "big5", "cp1252",
    "cp932", "koi8-r", "macRoman", "identity", "binary", "ucs-2", "euc-kr",
};
static const char *const translations[] = {
    "auto", "lf", "cr", "crlf", "binary", "auto lf", "lf crlf", "crlf auto", "cr auto", "platform",
};
static const char *const eofchars[] = {
    "", "\x1a", "A", "{\x1a {}}", "{x y}", "\x04", "\n", "{\x1a \x1a}",
};
static const char *const profiles[] = {"strict", "tcl8", "replace", "tcl8"};
static const size_t chunks[] = {1, 1, 2, 3, 4, 5, 7, 8, 13, 16, 31, 64, 100, 512, 4096, 65536};

static void run_op(Tcl_Channel chan, unsigned op) {
    unsigned arg = op >> 3;
    char buf[4096];
    Tcl_DString ds;
    Tcl_Obj *o;

    switch (op & 7) {
    case 0:
        Tcl_DStringInit(&ds);
        Tcl_Gets(chan, &ds);
        Tcl_DStringFree(&ds);
        break;
    case 1:
        Tcl_Read(chan, buf, (Tcl_Size)1 << (arg % 12));
        break;
    case 2:
        o = Tcl_NewObj();
        Tcl_IncrRefCount(o);
        Tcl_ReadChars(chan, o, arg ? (Tcl_Size)arg : -1, arg & 1);
        Tcl_DecrRefCount(o);
        break;
    case 3:
        Tcl_Seek(chan, (long long)((arg * 7) % 64) - 8, (int)(arg % 3));
        break;
    case 4:
        Tcl_Tell(chan);
        Tcl_InputBuffered(chan);
        Tcl_Eof(chan);
        break;
    case 5:
        Tcl_SetChannelOption(NULL, chan, "-translation", translations[arg % (sizeof translations / sizeof *translations)]);
        break;
    case 6:
        Tcl_SetChannelOption(NULL, chan, "-encoding", encs[arg % (sizeof encs / sizeof *encs)]);
        break;
    default:
        o = Tcl_NewObj();
        Tcl_IncrRefCount(o);
        Tcl_GetsObj(chan, o);
        Tcl_DecrRefCount(o);
        break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Channel chan;
    Mem *m;
    char bsize[16], buf[4096];
    size_t nops, i;
    int seekable;

    if (size < 5) return -1;
    nops = (data[4] % 32) + 1;
    if (size < 5 + nops) return -1;
    fz_init("fuzz");
    seekable = (data[2] >> 6) & 1;
    m = malloc(sizeof *m);
    m->data = data + 5 + nops;
    m->size = size - 5 - nops;
    m->pos = 0;
    m->chunk = chunks[data[3] & 15];
    chan = Tcl_CreateChannel(seekable ? &seekableType : &streamType, "fuzzchan", m, TCL_READABLE);

    snprintf(bsize, sizeof bsize, "%d", 1 + (data[2] & 15) * 37);
    Tcl_SetChannelOption(NULL, chan, "-buffersize", bsize);
    Tcl_SetChannelOption(NULL, chan, "-profile", profiles[(data[2] >> 4) & 3]);
    Tcl_SetChannelOption(NULL, chan, "-encoding", encs[data[0] % (sizeof encs / sizeof *encs)]);
    Tcl_SetChannelOption(NULL, chan, "-translation", translations[(data[1] & 7) % (sizeof translations / sizeof *translations)]);
    Tcl_SetChannelOption(NULL, chan, "-eofchar", eofchars[(data[1] >> 3) & 7]);

    for (i = 0; i < nops; i++) run_op(chan, data[5 + i]);
    for (i = 0; i < 100000 && Tcl_Read(chan, buf, sizeof buf) > 0; i++) {
    }
    Tcl_Close(NULL, chan);
    return 0;
}
