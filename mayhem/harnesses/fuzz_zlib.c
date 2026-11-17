/* zlib wrappers (tclZlib.c): one-shot Tcl_ZlibInflate with gzip-header extraction, and the
 * streaming Tcl_ZlibStreamPut/Get path, over the bundled zlib.
 * Input: byte 0 = format/mode, byte 1 = chunk size, rest = compressed bytes. */
#include "fuzz_common.h"

static const int formats[] = {TCL_ZLIB_FORMAT_RAW, TCL_ZLIB_FORMAT_ZLIB, TCL_ZLIB_FORMAT_GZIP,
                              TCL_ZLIB_FORMAT_AUTO};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    int fmt;
    uint8_t b;
    size_t chunk;

    if (size < 2) return -1;
    b = data[0];
    chunk = 1 + data[1];
    fmt = formats[b & 3];
    data += 2; size -= 2;
    interp = fz_new_interp(0);
    if (!(b & 4)) {
        Tcl_Obj *in = Tcl_NewByteArrayObj(data, (Tcl_Size)size), *hdr = NULL;
        Tcl_IncrRefCount(in);
        if (fmt == TCL_ZLIB_FORMAT_GZIP || fmt == TCL_ZLIB_FORMAT_AUTO) {
            hdr = Tcl_NewObj();
            Tcl_IncrRefCount(hdr);
        }
        Tcl_ZlibInflate(interp, fmt, in, (b & 8) ? (Tcl_Size)chunk : 0, hdr);
        if (hdr) Tcl_DecrRefCount(hdr);
        Tcl_DecrRefCount(in);
    } else {
        Tcl_ZlibStream zs;
        if (Tcl_ZlibStreamInit(interp, TCL_ZLIB_STREAM_INFLATE, fmt, 0, NULL, &zs) == TCL_OK) {
            size_t off = 0;
            size_t total = 0;
            while (off < size) {
                size_t c = size - off < chunk ? size - off : chunk;
                Tcl_Obj *in = Tcl_NewByteArrayObj(data + off, (Tcl_Size)c), *out = Tcl_NewObj();
                Tcl_Size got;
                off += c;
                Tcl_IncrRefCount(in); Tcl_IncrRefCount(out);
                if (Tcl_ZlibStreamPut(zs, in, off == size ? TCL_ZLIB_FINALIZE : TCL_ZLIB_NO_FLUSH) != TCL_OK) {
                    Tcl_DecrRefCount(in); Tcl_DecrRefCount(out);
                    break;
                }
                if (Tcl_ZlibStreamGet(zs, out, (b & 16) ? 1024 : -1) == TCL_OK) {
                    Tcl_GetByteArrayFromObj(out, &got);
                    total += (size_t)got;
                }
                Tcl_DecrRefCount(in); Tcl_DecrRefCount(out);
                if (Tcl_ZlibStreamEof(zs)) break;
            }
            (void)total;
            Tcl_ZlibStreamClose(zs);
        }
    }
    fz_free_interp(interp);
    return 0;
}
