/* `format` (Tcl_Format / Tcl_AppendFormatToObj in tclStringObj.c: %-spec parser, XPG
 * positions, bignum formatting) and `scan` (tclScan.c).
 * Input: byte 0 = mode, then format NUL args... (scan: format NUL string). */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[8], *r;
    int n;

    if (size < 1) return -1;
    interp = fz_new_interp(0);
    n = fz_split(data + 1, size - 1, w, 8);
    if (data[0] & 1) {
        r = Tcl_Format(interp, Tcl_GetString(w[0]), n - 1, w + 1);
        if (r) { Tcl_IncrRefCount(r); Tcl_DecrRefCount(r); }
    } else {
        Tcl_Obj *objv[3];
        objv[0] = fz_lit("scan");
        objv[1] = n > 1 ? w[1] : w[0];
        objv[2] = w[0];
        Tcl_IncrRefCount(objv[1]); Tcl_IncrRefCount(objv[2]);
        fz_call(interp, 3, objv);
        fz_release(objv, 3);
    }
    fz_release(w, n);
    fz_free_interp(interp);
    return 0;
}
