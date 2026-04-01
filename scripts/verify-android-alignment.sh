#!/usr/bin/env bash
# Verifies that all Android .so files have 16KB-aligned LOAD segments.
# Required for Google Play Android 15+ (APPS-9315).
#
# Usage: ./scripts/verify-android-alignment.sh [path/to/jniLibs]
# Defaults to ethers-ffi/ethers-rs-mobile/android/jniLibs

set -euo pipefail

JNILIBS_DIR="${1:-ethers-ffi/ethers-rs-mobile/android/jniLibs}"
EXPECTED_ALIGN="2**14"
ERRORS=0

if [ ! -d "$JNILIBS_DIR" ]; then
  echo "ERROR: Directory not found: $JNILIBS_DIR"
  echo "Build the Android libraries first (make -C ethers-ffi android)"
  exit 1
fi

for so_file in "$JNILIBS_DIR"/*/libethers_ffi.so; do
  if [ ! -f "$so_file" ]; then
    echo "WARNING: No .so files found in $JNILIBS_DIR"
    exit 1
  fi

  arch_dir=$(basename "$(dirname "$so_file")")
  echo "Checking $arch_dir/libethers_ffi.so..."

  # Extract LOAD segment alignments
  load_aligns=$(objdump -p "$so_file" 2>/dev/null | grep -A1 "LOAD" | grep "align" | awk '{print $NF}')

  if [ -z "$load_aligns" ]; then
    # Try llvm-objdump or readelf as fallback
    load_aligns=$(readelf -l "$so_file" 2>/dev/null | grep "LOAD" | awk '{print $NF}' || true)
    if [ -z "$load_aligns" ]; then
      echo "  ERROR: Could not read ELF LOAD segments from $so_file"
      ERRORS=$((ERRORS + 1))
      continue
    fi

    # readelf shows alignment as hex (e.g., 0x4000 = 16384)
    for align in $load_aligns; do
      align_dec=$((align))
      if [ "$align_dec" -lt 16384 ]; then
        echo "  FAIL: LOAD segment alignment $align ($align_dec bytes) < 16384 (16KB)"
        ERRORS=$((ERRORS + 1))
      else
        echo "  OK: LOAD segment alignment $align ($align_dec bytes) >= 16KB"
      fi
    done
  else
    # objdump shows alignment as 2**N
    for align in $load_aligns; do
      power=$(echo "$align" | sed 's/2\*\*//')
      if [ "$power" -lt 14 ]; then
        echo "  FAIL: LOAD segment alignment 2**$power < 2**14 (16KB)"
        ERRORS=$((ERRORS + 1))
      else
        echo "  OK: LOAD segment alignment 2**$power >= 2**14 (16KB)"
      fi
    done
  fi
done

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "FAILED: $ERRORS LOAD segment(s) have alignment < 16KB"
  echo "Ensure .cargo/config.toml sets rustflags with -Clink-arg=-z -Clink-arg=max-page-size=16384"
  exit 1
fi

echo ""
echo "PASSED: All Android .so files have 16KB-aligned LOAD segments"
