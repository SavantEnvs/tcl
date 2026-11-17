/* `regsub` (Tcl_RegsubObjCmd in tclCmdMZ.c: subSpec parsing, -command submatch passing).
 * Input: byte 0 = options, byte 1 = -start index, then RE NUL subject NUL subSpec.
 * Words go in as objv, never parsed as script; -command uses the fixed prefix `list`. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[3] = {NULL, NULL, NULL}, *objv[12];
    int n, objc = 0;
    uint8_t b;
    char start[8];

    if (size < 2) return -1;
    b = data[0];
    interp = fz_new_interp(0);
    n = fz_split(data + 2, size - 2, w, 3);
    objv[objc++] = fz_lit("regsub");
    if (b & 0x01) objv[objc++] = fz_lit("-all");
    if (b & 0x02) objv[objc++] = fz_lit("-nocase");
    if (b & 0x04) objv[objc++] = fz_lit("-expanded");
    if (b & 0x08) objv[objc++] = fz_lit("-line");
    if (b & 0x10) {
        snprintf(start, sizeof start, "%d", data[1] % 64);
        objv[objc++] = fz_lit("-start");
        objv[objc++] = fz_lit(start);
    }
    if (b & 0x20) objv[objc++] = fz_lit("-command");
    objv[objc++] = fz_lit("--");
    objv[objc] = w[0]; Tcl_IncrRefCount(objv[objc++]);
    objv[objc] = n > 1 ? w[1] : fz_lit("");
    if (n > 1) Tcl_IncrRefCount(objv[objc]);
    objc++;
    if (b & 0x20) objv[objc++] = fz_lit("list");
    else {
        objv[objc] = n > 2 ? w[2] : fz_lit("&");
        if (n > 2) Tcl_IncrRefCount(objv[objc]);
        objc++;
    }
    fz_call(interp, objc, objv);
    fz_release(objv, objc);
    fz_release(w, n);
    fz_flush_regexp_cache(interp);
    fz_free_interp(interp);
    return 0;
}
