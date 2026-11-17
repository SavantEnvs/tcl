/* String/UTF primitives: glob matcher Tcl_StringCaseMatch (tclUtil.c), UTF walking (tclUtf.c),
 * the `string` ensemble (tclCmdMZ.c), and `unicode` normalization (utf8proc via tclCmdMZ.c).
 * Input: byte 0 = selector, then pattern NUL string. */
#include "fuzz_common.h"

static const char *const classes[] = {
    "alnum", "alpha", "ascii", "boolean", "control", "dict", "digit", "double", "entier",
    "false", "graph", "integer", "list", "lower", "print", "punct", "space", "true", "upper",
    "wideinteger", "wordchar", "xdigit",
};
static const char *const unicodeOps[] = {"tonfc", "tonfd", "tonfkc", "tonfkd"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[2], *objv[6];
    int n;
    uint8_t b;
    const char *pat, *str, *p;
    Tcl_Size i;

    if (size < 1) return -1;
    b = data[0];
    interp = fz_new_interp(0);
    n = fz_split(data + 1, size - 1, w, 2);
    pat = Tcl_GetString(w[0]);
    str = Tcl_GetString(w[n - 1]);
    Tcl_StringCaseMatch(str, pat, 0);
    Tcl_StringCaseMatch(str, pat, TCL_MATCH_NOCASE);
    Tcl_NumUtfChars(str, -1);
    for (p = str, i = 0; *p && i < 100000; i++) p = Tcl_UtfNext(p);
    while (p > str && i-- > 0) p = Tcl_UtfPrev(p, str);

    objv[0] = fz_lit("string"); objv[1] = fz_lit("is");
    objv[2] = fz_lit(classes[b % (sizeof classes / sizeof classes[0])]);
    objv[3] = fz_lit("-strict"); objv[4] = w[n - 1]; Tcl_IncrRefCount(w[n - 1]);
    fz_call(interp, 5, objv); fz_release(objv, 5);

    objv[0] = fz_lit("string"); objv[1] = fz_lit("map");
    if (b & 0x80) { objv[2] = fz_lit("-nocase"); }
    else { objv[2] = NULL; }
    {
        Tcl_Obj *m = Tcl_NewListObj(0, NULL);
        Tcl_ListObjAppendElement(NULL, m, w[0]);
        Tcl_ListObjAppendElement(NULL, m, Tcl_NewStringObj("<>", 2));
        Tcl_IncrRefCount(m);
        Tcl_Obj *mv[5]; int mc = 0;
        mv[mc++] = objv[0]; mv[mc++] = objv[1];
        if (objv[2]) mv[mc++] = objv[2];
        mv[mc++] = m; mv[mc++] = w[n - 1]; Tcl_IncrRefCount(w[n - 1]);
        fz_call(interp, mc, mv);
        fz_release(mv, mc);
    }

    objv[0] = fz_lit("string");
    objv[1] = fz_lit((b & 0x40) ? "totitle" : ((b & 0x20) ? "toupper" : "tolower"));
    objv[2] = w[n - 1]; Tcl_IncrRefCount(w[n - 1]);
    fz_call(interp, 3, objv); fz_release(objv, 3);

    objv[0] = fz_lit("string"); objv[1] = fz_lit("trim");
    objv[2] = w[n - 1]; Tcl_IncrRefCount(w[n - 1]);
    objv[3] = w[0]; Tcl_IncrRefCount(w[0]);
    fz_call(interp, 4, objv); fz_release(objv, 4);

    objv[0] = fz_lit("unicode");
    objv[1] = fz_lit(unicodeOps[(b >> 3) & 3]);
    objv[2] = w[n - 1]; Tcl_IncrRefCount(w[n - 1]);
    fz_call(interp, 3, objv); fz_release(objv, 3);

    fz_release(w, n);
    fz_free_interp(interp);
    return 0;
}
