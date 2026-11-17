/* tclsh for the fuzz target `tclsh`: upstream's unix/tclAppInit.c (Tcl_Main, the zip-attached
 * library, script-file startup) with one extra AppInit step that removes every command able to
 * change state outside the process, so an input's result depends only on that input and nothing a
 * script does survives into the next input of the same container. Deleted, not hidden: a
 * master interp can call hidden commands back with `interp invokehidden`. */
#include <stdio.h>
#define TCL_LOCAL_APPINIT FuzzAppInit
#include "../unix/tclAppInit.c"

extern int Tcl_AppInit(Tcl_Interp *interp);

/* Filesystem and process side effects (exec file open socket cd exit load unload source zipfs
 * glob), plus the commands that block on the event loop or wall clock (after vwait update).
 * `interp` is replaced by a stub that only answers `interp issafe` (the script library's autoloader
 * asks it, so `clock` and friends keep loading): a fresh unsafe child interp would bring every
 * deleted command back. The ensembles' subcommands live in ::tcl::file and ::tcl::zipfs and are
 * callable by full name, so those namespaces go too. The autoloader needs `source` and `file`, so
 * `clock`, the one script-library module worth the start-up time, is loaded first; the other
 * autoloaded procs (parray, history, ...) are not available. */
static const char restrictScript[] =
    "catch {clock format 0 -timezone UTC}\n"
    "foreach c {exec file open socket cd exit interp load unload source zipfs glob after vwait update} {\n"
    "    rename $c {}\n"
    "}\n"
    "namespace delete ::tcl::file ::tcl::zipfs\n"
    "proc interp {args} {\n"
    "    if {$args eq {issafe}} {return 0}\n"
    "    return -code error {interp: not available in this fuzz target}\n"
    "}\n";

int FuzzAppInit(Tcl_Interp *interp) {
    if (Tcl_AppInit(interp) != TCL_OK) return TCL_ERROR;
    if (Tcl_EvalEx(interp, restrictScript, -1, TCL_EVAL_GLOBAL) != TCL_OK) {
        fprintf(stderr, "tclsh_restricted: %s\n", Tcl_GetStringResult(interp));
        return TCL_ERROR;
    }
    return TCL_OK;
}
