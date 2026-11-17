/* `lseq` (tclArithSeries.c, Tcl_LseqObjCmd) and list operations on the arithmetic-series result.
 * Input: up to 6 NUL-separated words (numbers, `to`, `count`, `by`, `..`, expressions). */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_interp(0);
    Tcl_Obj *objv[7];
    int n = fz_split(data, size, objv + 1, 6);
    objv[0] = fz_lit("lseq");
    if (fz_call(interp, n + 1, objv) == TCL_OK) {
        Tcl_Obj *l = Tcl_GetObjResult(interp), *e, *ops[4];
        Tcl_Size len = 0;
        Tcl_IncrRefCount(l);
        if (Tcl_ListObjLength(interp, l, &len) == TCL_OK && len > 0) {
            Tcl_ListObjIndex(interp, l, 0, &e);
            Tcl_ListObjIndex(interp, l, len - 1, &e);
            Tcl_ListObjIndex(interp, l, len / 2, &e);
            ops[0] = fz_lit("lindex"); ops[1] = l; Tcl_IncrRefCount(l); ops[2] = fz_lit("end-1");
            fz_call(interp, 3, ops); fz_release(ops, 3);
            ops[0] = fz_lit("lrange"); ops[1] = l; Tcl_IncrRefCount(l); ops[2] = fz_lit("1"); ops[3] = fz_lit("end-1");
            fz_call(interp, 4, ops); fz_release(ops, 4);
            ops[0] = fz_lit("lreverse"); ops[1] = l; Tcl_IncrRefCount(l);
            fz_call(interp, 2, ops); fz_release(ops, 2);
            ops[0] = fz_lit("lsearch"); ops[1] = l; Tcl_IncrRefCount(l); ops[2] = fz_lit("3");
            fz_call(interp, 3, ops); fz_release(ops, 3);
            if (len < 4096) Tcl_GetString(l); /* string rep of a modest series */
        }
        Tcl_DecrRefCount(l);
    }
    fz_release(objv, n + 1);
    fz_free_interp(interp);
    return 0;
}
