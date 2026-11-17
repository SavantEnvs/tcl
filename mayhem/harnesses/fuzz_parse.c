/* Script tokenizer without evaluation (tclParse.c): Tcl_ParseCommand over the whole buffer,
 * Tcl_ParseVarName / Tcl_ParseBraces / Tcl_ParseQuotedString where the buffer starts with the
 * construct each documents as its precondition, Tcl_CommandComplete, and backslash-only
 * Tcl_SubstObj. Input: the script text. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_interp(0);
    char *buf = malloc(size + 1);
    const char *p, *end, *term;
    Tcl_Parse parse;
    Tcl_Obj *o, *r;

    memcpy(buf, data, size);
    buf[size] = 0;
    p = buf; end = buf + size;
    while (p < end) {
        if (Tcl_ParseCommand(interp, p, end - p, 0, &parse) != TCL_OK) break;
        p = parse.commandStart + parse.commandSize;
        if (parse.commandSize <= 0) { Tcl_FreeParse(&parse); break; }
        Tcl_FreeParse(&parse);
    }
    Tcl_ResetResult(interp);
    if (size && buf[0] == '$' && Tcl_ParseVarName(interp, buf, (Tcl_Size)size, &parse, 0) == TCL_OK)
        Tcl_FreeParse(&parse);
    if (size && buf[0] == '{' && Tcl_ParseBraces(interp, buf, (Tcl_Size)size, &parse, 0, &term) == TCL_OK)
        Tcl_FreeParse(&parse);
    if (size && buf[0] == '"' && Tcl_ParseQuotedString(interp, buf, (Tcl_Size)size, &parse, 0, &term) == TCL_OK)
        Tcl_FreeParse(&parse);
    Tcl_CommandComplete(buf);
    o = Tcl_NewStringObj(buf, (Tcl_Size)size);
    Tcl_IncrRefCount(o);
    r = Tcl_SubstObj(interp, o, TCL_SUBST_BACKSLASHES);
    if (r) { Tcl_IncrRefCount(r); Tcl_DecrRefCount(r); }
    Tcl_DecrRefCount(o);
    free(buf);
    fz_free_interp(interp);
    return 0;
}
