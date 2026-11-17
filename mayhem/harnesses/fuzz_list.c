/* List and dict string parsing (tclUtil.c TclFindElement / quoting, tclListObj.c, tclDictObj.c).
 * Splits the input as a list, re-quotes the elements with Tcl_Merge and asserts that re-splitting
 * the merged string yields the same elements (Tcl_Merge's documented contract), parses it as a
 * dict, and sorts/searches it. Input: the list text. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_interp(0);
    char *buf = malloc(size + 1);
    Tcl_Size argc, argc2, i, len;
    const char **argv, **argv2;
    Tcl_Obj *o, **elems, *objv[4];

    memcpy(buf, data, size);
    buf[size] = 0;
    if (Tcl_SplitList(interp, buf, &argc, &argv) == TCL_OK) {
        char *merged = Tcl_Merge(argc, argv);
        if (Tcl_SplitList(NULL, merged, &argc2, &argv2) != TCL_OK || argc2 != argc) {
            fprintf(stderr, "Tcl_Merge round trip broke the list\n");
            abort();
        }
        for (i = 0; i < argc; i++)
            if (strcmp(argv[i], argv2[i]) != 0) {
                fprintf(stderr, "Tcl_Merge round trip changed element %ld\n", (long)i);
                abort();
            }
        Tcl_Free((void *)argv2);
        Tcl_Free(merged);
        Tcl_Free((void *)argv);
    }
    Tcl_ResetResult(interp);
    o = Tcl_NewStringObj((const char *)data, (Tcl_Size)size);
    Tcl_IncrRefCount(o);
    Tcl_ListObjGetElements(interp, o, &len, &elems);
    Tcl_DecrRefCount(o);
    o = Tcl_NewStringObj((const char *)data, (Tcl_Size)size);
    Tcl_IncrRefCount(o);
    Tcl_DictObjSize(interp, o, &len);
    Tcl_DecrRefCount(o);
    objv[0] = fz_lit("lsort");
    objv[1] = fz_lit((size && (data[0] & 1)) ? "-dictionary" : "-unique");
    objv[2] = Tcl_NewStringObj((const char *)data, (Tcl_Size)size);
    Tcl_IncrRefCount(objv[2]);
    fz_call(interp, 3, objv);
    fz_release(objv, 3);
    objv[0] = fz_lit("lsearch");
    objv[1] = fz_lit("-all");
    objv[2] = Tcl_NewStringObj((const char *)data, (Tcl_Size)size);
    Tcl_IncrRefCount(objv[2]);
    objv[3] = fz_lit("*a*");
    fz_call(interp, 4, objv);
    fz_release(objv, 4);
    free(buf);
    fz_free_interp(interp);
    return 0;
}
