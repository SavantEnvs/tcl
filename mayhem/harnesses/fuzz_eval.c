/* Script evaluation in a fresh safe interpreter: parser, bytecode compiler, execution engine and
 * every built-in command a safe interp exposes (file/exec/socket/exit are hidden by
 * Tcl_MakeSafe). Input: the script. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_safe_interp();
    char *script = fz_cstr(data, size);
    Tcl_EvalEx(interp, script, (Tcl_Size)size, TCL_EVAL_GLOBAL);
    free(script);
    fz_flush_regexp_cache(interp);
    fz_free_safe_interp(interp);
    return 0;
}
