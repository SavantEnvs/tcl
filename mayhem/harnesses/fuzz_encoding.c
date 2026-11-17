/* Encoding conversion (tclEncoding.c: utf-8/16/32, cesu-8, table and escape encodings).
 * Input: byte 0 = encoding, byte 1 = profile + streaming buffer size, rest = bytes.
 * Decodes with the one-shot DString API and with the streaming API into a small buffer,
 * then encodes the result (and the raw bytes) back. */
#include "fuzz_common.h"

static const char *const encs[] = {
    "utf-8", "utf-16", "utf-16le", "utf-16be", "utf-32", "utf-32le", "utf-32be", "ucs-2",
    "cesu-8", "iso2022-jp", "iso2022", "iso2022-kr", "shiftjis", "euc-jp", "euc-kr", "euc-cn",
    "gb2312", "big5", "cp1252", "cp932", "cp936", "cp949", "cp950", "iso8859-1", "iso8859-2",
    "koi8-r", "macRoman", "ascii", "identity", "unicode", "jis0208", "gb12345",
};
static const int profiles[] = {
    TCL_ENCODING_PROFILE_STRICT, TCL_ENCODING_PROFILE_TCL8, TCL_ENCODING_PROFILE_REPLACE,
    TCL_ENCODING_PROFILE_TCL8,
};

static void stream(Tcl_Encoding e, const char *src, Tcl_Size len, int flags, Tcl_Size dstLen, int toUtf) {
    Tcl_EncodingState state = NULL;
    char dst[260];
    int read, wrote, chars, rc, f = flags | TCL_ENCODING_START, guard = 0;
    Tcl_Size off = 0;
    /* All remaining source is handed over on each call, so END is always set; the small dst
     * buffer forces TCL_CONVERT_NOSPACE round trips through the encoder state. */
    for (;;) {
        if (toUtf)
            rc = Tcl_ExternalToUtf(NULL, e, src + off, len - off, f | TCL_ENCODING_END, &state,
                                   dst, dstLen, &read, &wrote, &chars);
        else
            rc = Tcl_UtfToExternal(NULL, e, src + off, len - off, f | TCL_ENCODING_END, &state,
                                   dst, dstLen, &read, &wrote, &chars);
        off += read;
        f &= ~TCL_ENCODING_START;
        if (rc != TCL_CONVERT_NOSPACE || ++guard > 100000 || (read == 0 && wrote == 0)) break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Tcl_Encoding e;
    Tcl_DString ds, ds2;
    Tcl_Size errLoc, dstLen;
    int flags;

    if (size < 2) return -1;
    fz_init("fuzz");
    e = Tcl_GetEncoding(NULL, encs[data[0] % (sizeof encs / sizeof encs[0])]);
    if (!e) return 0;
    flags = profiles[data[1] & 3];
    dstLen = 4 + (data[1] >> 2) * 4; /* 4..256; the API needs room for at least one char */
    data += 2; size -= 2;

    Tcl_DStringInit(&ds);
    Tcl_ExternalToUtfDStringEx(NULL, e, (const char *)data, (Tcl_Size)size, flags, &ds, &errLoc);
    Tcl_DStringInit(&ds2);
    Tcl_UtfToExternalDStringEx(NULL, e, Tcl_DStringValue(&ds), Tcl_DStringLength(&ds), flags, &ds2, &errLoc);
    stream(e, Tcl_DStringValue(&ds), Tcl_DStringLength(&ds), flags, dstLen, 0);
    Tcl_DStringFree(&ds2);
    Tcl_DStringFree(&ds);

    stream(e, (const char *)data, (Tcl_Size)size, flags, dstLen, 1);
    {
        /* Raw bytes as (possibly invalid) UTF-8 source, NUL-terminated as the API requires. */
        char *raw = fz_cstr(data, size);
        Tcl_DStringInit(&ds);
        Tcl_UtfToExternalDStringEx(NULL, e, raw, (Tcl_Size)size, flags, &ds, &errLoc);
        Tcl_DStringFree(&ds);
        free(raw);
    }
    Tcl_FreeEncoding(e);
    return 0;
}
