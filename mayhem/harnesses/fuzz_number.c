/* Number/index/boolean parsing: TclParseNumber + double conversion (tclStrToD.c), integer
 * getters (tclObj.c), index parsing (tclUtil.c), libtommath radix reading.
 * Input: byte 0 = endValue for Tcl_GetIntForIndex, rest = the string. */
#include "fuzz_common.h"
#include "tclTomMath.h"

static Tcl_Obj *fresh(const uint8_t *d, size_t n) {
    Tcl_Obj *o = Tcl_NewStringObj((const char *)d, (Tcl_Size)n);
    Tcl_IncrRefCount(o);
    return o;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *o;
    long l; Tcl_WideInt w; Tcl_WideUInt uw; double d; int i, bo; Tcl_Size idx;
    mp_int big;
    char buf[TCL_DOUBLE_SPACE];

    if (size < 1) return -1;
    interp = fz_new_interp(0);
    const uint8_t *s = data + 1; size_t n = size - 1;

    o = fresh(s, n); Tcl_GetLongFromObj(interp, o, &l); Tcl_DecrRefCount(o);
    o = fresh(s, n); Tcl_GetIntFromObj(interp, o, &i); Tcl_DecrRefCount(o);
    o = fresh(s, n); Tcl_GetWideIntFromObj(interp, o, &w); Tcl_DecrRefCount(o);
    o = fresh(s, n); Tcl_GetWideUIntFromObj(interp, o, &uw); Tcl_DecrRefCount(o);
    o = fresh(s, n); Tcl_GetBooleanFromObj(interp, o, &bo); Tcl_DecrRefCount(o);
    o = fresh(s, n); Tcl_GetIntForIndex(interp, o, (Tcl_Size)data[0] - 1, &idx); Tcl_DecrRefCount(o);
    o = fresh(s, n);
    if (Tcl_GetDoubleFromObj(interp, o, &d) == TCL_OK) {
        Tcl_PrintDouble(NULL, d, buf);
        Tcl_Obj *r = Tcl_NewStringObj(buf, -1);
        double d2;
        Tcl_IncrRefCount(r);
        Tcl_GetDoubleFromObj(NULL, r, &d2);
        Tcl_DecrRefCount(r);
    }
    Tcl_DecrRefCount(o);
    o = fresh(s, n);
    if (Tcl_GetBignumFromObj(interp, o, &big) == TCL_OK) {
        Tcl_Obj *r = Tcl_NewBignumObj(&big);
        Tcl_IncrRefCount(r);
        Tcl_GetString(r);
        Tcl_DecrRefCount(r);
    }
    Tcl_DecrRefCount(o);
    /* The generic number getter used by expr and the [string is] classes. */
    o = fresh(s, n);
    { void *cd; int type; Tcl_GetNumberFromObj(interp, o, &cd, &type); }
    Tcl_DecrRefCount(o);
    fz_free_interp(interp);
    return 0;
}
