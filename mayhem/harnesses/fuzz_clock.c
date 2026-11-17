/* `clock scan` (free-form scanner tclDate.c, -format scanner tclClockFmt.c, tclStrIdxTree.c)
 * and `clock format` of the result. Input: byte 0 = mode, then date-string NUL format. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[2], *objv[12], *t;
    int n, objc = 0, useFmt;
    uint8_t b;

    if (size < 1) return -1;
    b = data[0];
    interp = fz_new_interp(1);
    n = fz_split(data + 1, size - 1, w, 2);
    useFmt = (b & 1) && n == 2;
    objv[objc++] = fz_lit("clock");
    objv[objc++] = fz_lit("scan");
    objv[objc] = w[0]; Tcl_IncrRefCount(objv[objc++]);
    objv[objc++] = fz_lit("-gmt");
    objv[objc++] = fz_lit("1");
    if (useFmt) {
        objv[objc++] = fz_lit("-format");
        objv[objc] = w[1]; Tcl_IncrRefCount(objv[objc++]);
    }
    if (b & 2) {
        objv[objc++] = fz_lit("-base");
        objv[objc++] = fz_lit("1000000000");
    }
    if (b & 4) {
        objv[objc++] = fz_lit("-validate");
        objv[objc++] = fz_lit("1");
    }
    if (fz_call(interp, objc, objv) == TCL_OK) {
        Tcl_Obj *fo[7];
        int fc = 0;
        t = Tcl_GetObjResult(interp);
        Tcl_IncrRefCount(t);
        fo[fc++] = fz_lit("clock");
        fo[fc++] = fz_lit("format");
        fo[fc++] = t;
        fo[fc++] = fz_lit("-gmt");
        fo[fc++] = fz_lit("1");
        if (n == 2) {
            fo[fc++] = fz_lit("-format");
            fo[fc] = w[1]; Tcl_IncrRefCount(fo[fc++]);
        }
        fz_call(interp, fc, fo);
        fz_release(fo, fc);
    }
    fz_release(objv, objc);
    fz_release(w, n);
    fz_free_interp(interp);
    return 0;
}
