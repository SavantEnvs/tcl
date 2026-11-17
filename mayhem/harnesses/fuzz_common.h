/*
 * Shared helpers for the Tcl libFuzzer harnesses (mayhem/harnesses/fuzz_*.c).
 *
 * State policy: every input gets a FRESH interpreter (fz_new_interp / fz_new_safe_interp), deleted
 * after the input, so no variables, procs, namespaces, clock/format caches or literals survive.
 * Process-global state that remains: (1) loaded encoding tables, read-only once loaded from
 * library/encoding; (2) the per-thread compiled-regexp cache (30 entries, tclRegexp.c), which
 * fz_flush_regexp_cache() evicts after every input so a fuzz pattern is never served from a
 * previous input's compile; (3) zipfs mounts, which fuzz_zipfs unmounts after every input.
 * fuzz_channel makes no interpreter: its channel is created and closed inside each input.
 */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tcl.h"

#ifndef FUZZ_TCL_LIBRARY
#error "build.sh passes -DFUZZ_TCL_LIBRARY=<src>/library"
#endif

static int fz_initialized;

static void fz_init(const char *argv0) {
    if (fz_initialized) return;
    fz_initialized = 1;
    /* The static libtcl has no attached zip; point it at the source tree's script library
     * (init.tcl, clock.tcl, the encoding tables). An explicit TCL_LIBRARY in the env wins. */
    setenv("TCL_LIBRARY", FUZZ_TCL_LIBRARY, 0);
    Tcl_FindExecutable(argv0);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    fz_init(argc && *argc > 0 ? (*argv)[0] : "fuzz");
    return 0;
}

/* Fresh interpreter. withInit=1 also sources init.tcl (needed by script-library parts: clock). */
static Tcl_Interp *fz_new_interp(int withInit) {
    Tcl_Interp *interp;
    fz_init("fuzz");
    interp = Tcl_CreateInterp();
    if (withInit && Tcl_Init(interp) != TCL_OK) {
        fprintf(stderr, "Tcl_Init failed: %s\n", Tcl_GetStringResult(interp));
        abort(); /* environment problem, not an input problem */
    }
    return interp;
}

static void fz_free_interp(Tcl_Interp *interp) {
    Tcl_DeleteInterp(interp);
}

/* Evict every entry of the per-thread regexp cache (NUM_REGEXPS = 30, LRU) by touching 31
 * fixed patterns: the last one is a miss whenever a fuzz pattern is still cached, and pushes it out. */
static void fz_flush_regexp_cache(Tcl_Interp *interp) {
    char pat[32];
    int i;
    for (i = 0; i < 31; i++) {
        snprintf(pat, sizeof pat, "fz%dflush", i);
        Tcl_RegExpCompile(interp, pat);
    }
    Tcl_ResetResult(interp);
}

/* Split data at NUL bytes into at most max words (the last word keeps the remaining bytes,
 * NULs included). Returns the number of words; each is a new refcounted string object. */
static int fz_split(const uint8_t *data, size_t size, Tcl_Obj **words, int max) {
    int n = 0;
    size_t start = 0, i;
    for (i = 0; i < size && n < max - 1; i++) {
        if (data[i] == 0) {
            words[n] = Tcl_NewStringObj((const char *)data + start, (Tcl_Size)(i - start));
            Tcl_IncrRefCount(words[n++]);
            start = i + 1;
        }
    }
    words[n] = Tcl_NewStringObj((const char *)data + start, (Tcl_Size)(size - start));
    Tcl_IncrRefCount(words[n++]);
    return n;
}

static void fz_release(Tcl_Obj **objs, int n) {
    int i;
    for (i = 0; i < n; i++) if (objs[i]) Tcl_DecrRefCount(objs[i]);
}

/* NUL-terminated copy of the input: Tcl's C API takes scripts and UTF-8 text as NUL-terminated
 * buffers even when a length is passed (doc/Eval.3: "null-terminated TUTF-8 byte sequence"), and
 * its scanners rely on the terminator. Caller frees. */
static char *fz_cstr(const uint8_t *data, size_t size) {
    char *s = malloc(size + 1);
    if (size) memcpy(s, data, size);
    s[size] = 0;
    return s;
}

/* Invoke a command with the given words as objv (never parsed as a script). */
static int fz_call(Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
    return Tcl_EvalObjv(interp, objc, objv, TCL_EVAL_GLOBAL);
}

static Tcl_Obj *fz_lit(const char *s) {
    Tcl_Obj *o = Tcl_NewStringObj(s, -1);
    Tcl_IncrRefCount(o);
    return o;
}

/* Fresh SAFE interpreter for script/expr inputs: a safe child (Tcl_CreateChild isSafe=1, so no
 * file/exec/socket/exit/load) of a fresh parent; `after`, `vwait` and `update` are removed (they
 * block on the event loop / wall clock); deterministic bounds on command count and recursion depth
 * keep runaway scripts finite without any timer. fz_free_safe_interp deletes both. */
static Tcl_Interp *fz_new_safe_interp(void) {
    static const char *const blocking[] = {"after", "vwait", "update", NULL};
    Tcl_Interp *parent = fz_new_interp(0), *interp;
    int i;
    interp = Tcl_CreateChild(parent, "fz", 1);
    if (!interp) {
        fprintf(stderr, "Tcl_CreateChild failed: %s\n", Tcl_GetStringResult(parent));
        abort();
    }
    for (i = 0; blocking[i]; i++) Tcl_DeleteCommand(interp, blocking[i]);
    Tcl_LimitSetCommands(interp, 20000);
    Tcl_LimitTypeSet(interp, TCL_LIMIT_COMMANDS);
    Tcl_SetRecursionLimit(interp, 200);
    return interp;
}

static void fz_free_safe_interp(Tcl_Interp *interp) {
    Tcl_DeleteInterp(Tcl_GetParent(interp)); /* deletes the child too */
}

#endif
