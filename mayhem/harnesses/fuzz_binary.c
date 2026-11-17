/* `binary` (tclBinary.c): format-spec parser for scan/format, field readers, and the
 * base64/hex/uuencode decoders/encoders. Input: byte 0 = mode, then NUL-separated words. */
#include "fuzz_common.h"

static const char *const codecs[] = {"base64", "hex", "uuencode"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[8], *objv[20];
    int n, objc = 0, i;
    uint8_t b;

    if (size < 1) return -1;
    b = data[0];
    interp = fz_new_interp(0);
    switch (b % 4) {
    case 0: { /* binary scan <data> <fmt> v0..v7 ; fmt NUL raw-data-bytes */
        const uint8_t *p = data + 1, *z = memchr(p, 0, size - 1);
        size_t fl = z ? (size_t)(z - p) : size - 1;
        n = 0;
        objv[objc++] = fz_lit("binary");
        objv[objc++] = fz_lit("scan");
        objv[objc] = z ? Tcl_NewByteArrayObj(z + 1, (Tcl_Size)(size - 1 - fl - 1))
                       : Tcl_NewByteArrayObj(NULL, 0);
        Tcl_IncrRefCount(objv[objc++]);
        objv[objc] = Tcl_NewStringObj((const char *)p, (Tcl_Size)fl);
        Tcl_IncrRefCount(objv[objc++]);
        for (i = 0; i < 8; i++) {
            char v[4]; snprintf(v, sizeof v, "v%d", i);
            objv[objc++] = fz_lit(v);
        }
        break;
    }
    case 1: /* binary format <fmt> args... */
        n = fz_split(data + 1, size - 1, w, 8);
        objv[objc++] = fz_lit("binary");
        objv[objc++] = fz_lit("format");
        for (i = 0; i < n; i++) { objv[objc] = w[i]; Tcl_IncrRefCount(objv[objc++]); }
        break;
    default: /* binary decode|encode <codec> ?-strict? <data> */
        n = 0;
        objv[objc++] = fz_lit("binary");
        objv[objc++] = fz_lit((b % 4) == 2 ? "decode" : "encode");
        objv[objc++] = fz_lit(codecs[(b >> 2) % 3]);
        if ((b % 4) == 2 && (b & 0x20)) objv[objc++] = fz_lit("-strict");
        if ((b % 4) == 3 && (b & 0x20)) { objv[objc++] = fz_lit("-maxlen"); objv[objc++] = fz_lit("17"); }
        objv[objc++] = (b % 4) == 2 ? Tcl_NewStringObj((const char *)data + 1, (Tcl_Size)size - 1)
                                    : Tcl_NewByteArrayObj(data + 1, (Tcl_Size)size - 1);
        Tcl_IncrRefCount(objv[objc - 1]);
        break;
    }
    fz_call(interp, objc, objv);
    fz_release(objv, objc);
    fz_release(w, n);
    fz_free_interp(interp);
    return 0;
}
