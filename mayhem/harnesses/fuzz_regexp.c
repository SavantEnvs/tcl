/* Regexp engine (regcomp.c, regexec.c, rege_dfa.c, tclRegexp.c) through the public
 * Tcl_GetRegExpFromObj / Tcl_RegExpExecObj / Tcl_RegExpGetInfo API.
 * Input: byte 0 = flags, then pattern NUL subject. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp;
    Tcl_Obj *w[2];
    Tcl_RegExp re;
    int n, cflags = 0, eflags = 0, rc;
    Tcl_Size off = 0, len, guard = 0;
    uint8_t b;

    if (size < 1) return -1;
    b = data[0];
    cflags |= (b & 0x01) ? TCL_REG_ADVANCED : TCL_REG_EXTENDED;
    if (b & 0x02) cflags |= TCL_REG_NOCASE;
    if (b & 0x04) cflags |= TCL_REG_EXPANDED;
    if (b & 0x08) cflags |= TCL_REG_NEWLINE;
    if (b & 0x10) cflags = (cflags & ~(TCL_REG_ADVANCED | TCL_REG_EXTENDED)) | TCL_REG_QUOTE;
    if (b & 0x20) eflags |= TCL_REG_NOTBOL;

    interp = fz_new_interp(0);
    n = fz_split(data + 1, size - 1, w, 2);
    re = Tcl_GetRegExpFromObj(interp, w[0], cflags);
    if (re && n == 2) {
        len = Tcl_GetCharLength(w[1]);
        /* Walk all matches like `regexp -all -inline`. */
        while (off <= len && guard++ < 64) {
            Tcl_RegExpInfo info;
            rc = Tcl_RegExpExecObj(interp, re, w[1], off, -1, eflags | (off ? TCL_REG_NOTBOL : 0));
            if (rc != 1) break;
            Tcl_RegExpGetInfo(re, &info);
            if (info.matches[0].end <= 0) off++;
            else off += info.matches[0].end;
        }
    }
    fz_release(w, n);
    fz_flush_regexp_cache(interp);
    fz_free_interp(interp);
    return 0;
}
