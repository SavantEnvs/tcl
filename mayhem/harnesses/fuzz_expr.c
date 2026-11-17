/* Expression parser/compiler (tclCompExpr.c, tclParse.c Tcl_ParseExpr) and arithmetic /
 * math functions (tclExecute.c, tclBasic.c, bignums) in a fresh safe interpreter.
 * Input: the expression. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_safe_interp();
    Tcl_Obj *e = Tcl_NewStringObj((const char *)data, (Tcl_Size)size), *res = NULL;
    Tcl_Parse parse;
    char *text = fz_cstr(data, size);
    Tcl_IncrRefCount(e);
    if (Tcl_ParseExpr(interp, text, (Tcl_Size)size, &parse) == TCL_OK)
        Tcl_FreeParse(&parse);
    free(text);
    Tcl_ResetResult(interp);
    if (Tcl_ExprObj(interp, e, &res) == TCL_OK && res) {
        Tcl_GetString(res);
        Tcl_DecrRefCount(res);
    }
    Tcl_DecrRefCount(e);
    fz_free_safe_interp(interp);
    return 0;
}
