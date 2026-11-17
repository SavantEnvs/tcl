#!/usr/bin/env bash
# mayhem/build.sh — build Tcl's fuzz targets and its test runner (runs as `mayhem` in /mayhem).
#
#  1. mayhem/build-fuzz: libtcl + tclsh (static, --disable-shared) with $SANITIZER_FLAGS,
#     SanCov (-fsanitize=fuzzer-no-link) and DWARF 3. -DPURIFY makes ckalloc call malloc
#     directly, so ASan sees every Tcl allocation instead of the zippy allocator's pools.
#     --enable-symbols drops upstream's -DNDEBUG so Tcl's own assert()s stay live (its -g is
#     overridden by the later -gdwarf-3).
#  2. mayhem/out/<fuzz_*>: each harness in mayhem/harnesses linked against that libtcl, once with
#     libFuzzer and once with $STANDALONE_FUZZ_MAIN (<name>-standalone); mayhem/out/tclsh, which is
#     upstream's tclsh built from mayhem/tclsh_restricted.c (state-changing commands removed).
#  3. mayhem/build-test: an independent normal-flags build of `tcltest` for mayhem/test.sh.
#
# zlib: the base image ships zlib1g-dev, so configure links the system zlib.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
OUT="$M/out"
mkdir -p "$OUT"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$OUT/lsan_off.o"

# 1) sanitized + coverage-instrumented libtcl and tclsh. tclsh is relinked with lsan_off.o (leak
#    detection off, SPEC 6.2 item 15): otherwise LeakSanitizer aborts it with exit 1 whenever it runs
#    under ptrace, which is how Mayhem's sanity probe runs a file-input target. It also swaps
#    tclAppInit.o for tclsh_restricted.o, which deletes exec/file/open/socket/... after Tcl_Init.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -DPURIFY"
mkdir -p "$M/build-fuzz"
(
  cd "$M/build-fuzz"
  if [ ! -f config.status ]; then
    "$SRC/unix/configure" --disable-shared --enable-symbols CC="$CC" CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
  fi
  make -j"$MAYHEM_JOBS" binaries
  rm -f tclsh
  $CC $FUZZ_CFLAGS -I"$SRC/generic" -I"$SRC/unix" -I"$SRC/libtommath" -c "$M/tclsh_restricted.c" -o "$OUT/tclsh_restricted.o"
  make tclsh TCLSH_OBJS="$OUT/tclsh_restricted.o $OUT/lsan_off.o"
)
LIBTCL=$(ls "$M"/build-fuzz/libtcl[0-9]*.a | grep -v stub | head -1)
TCL_LIBS=$(. "$M/build-fuzz/tclConfig.sh" && echo "$TCL_LIBS")
cp "$M/build-fuzz/tclsh" "$OUT/tclsh"

# 2) harnesses
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
HFLAGS=(-I"$SRC/generic" -I"$SRC/unix" -I"$SRC/libtommath" -I"$M/harnesses" "-DFUZZ_TCL_LIBRARY=\"$SRC/library\"")
for h in "$M"/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${HFLAGS[@]}" -c "$h" -o "$OUT/$name.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" \
      "$LIBTCL" $TCL_LIBS -o "$OUT/$name"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OUT/standalone_main.o" "$OUT/$name.o" \
      "$OUT/lsan_off.o" "$LIBTCL" $TCL_LIBS -o "$OUT/$name-standalone"
done

# 3) test runner with the project's normal flags (no sanitizers, no DWARF pinning)
mkdir -p "$M/build-test"
(
  cd "$M/build-test"
  if [ ! -f config.status ]; then
    env -u CFLAGS -u LDFLAGS "$SRC/unix/configure" --disable-shared CC="$CC" \
        CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  fi
  make -j"$MAYHEM_JOBS" tcltest
)
echo "build.sh: done"
ls -l "$OUT"
