/* ZIP archives mounted by zipfs (tclZipfs.c: EOCD / central directory parsing, member open,
 * inflate, zip decryption) through the exported TclZipfs_MountBuffer. Every member is listed,
 * stat'ed and read; the mount is removed after each input. Input: the archive bytes. */
#include "fuzz_common.h"

static const char walk[] =
    "foreach f [zipfs list -glob [zipfs root]fuzzmnt/*] {\n"
    "    catch {file stat $f st}\n"
    "    catch {zipfs info $f}\n"
    "    catch {set c [open $f rb]; read $c; seek $c 0; read $c 7; close $c}\n"
    "}\n"
    "catch {glob -directory [zipfs root]fuzzmnt *}\n";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Interp *interp = fz_new_interp(0);
    if (TclZipfs_MountBuffer(interp, data, size, "fuzzmnt", 1) == TCL_OK) {
        Tcl_EvalEx(interp, walk, -1, TCL_EVAL_GLOBAL);
        TclZipfs_Unmount(interp, "fuzzmnt");
    }
    fz_free_interp(interp);
    return 0;
}
