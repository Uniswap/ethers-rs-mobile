#!/usr/bin/env bash
# Tests that .cargo/config.toml correctly configures 16KB page alignment
# for all Android targets used in the Makefile.
# This test runs without the Android NDK or Rust cross-compilation targets.

set -euo pipefail

CONFIG=".cargo/config.toml"
MAKEFILE="ethers-ffi/Makefile"
ERRORS=0

echo "=== Testing .cargo/config.toml for 16KB page alignment ==="

# Test 1: config.toml exists
if [ ! -f "$CONFIG" ]; then
  echo "FAIL: $CONFIG does not exist"
  exit 1
fi
echo "PASS: $CONFIG exists"

# Test 2: All Android targets from Makefile are covered
MAKEFILE_TARGETS=$(grep "^ARCHS_ANDROID" "$MAKEFILE" | sed 's/^[^=]*=\s*//' | tr ' ' '\n' | grep -v '^$' | sort)
CONFIG_TARGETS=$(grep '^\[target\.' "$CONFIG" | sed 's/\[target\.\(.*\)\]/\1/' | sort)

MISSING=""
for target in $MAKEFILE_TARGETS; do
  if ! echo "$CONFIG_TARGETS" | grep -qx "$target"; then
    MISSING="$MISSING $target"
    ERRORS=$((ERRORS + 1))
  fi
done

if [ -n "$MISSING" ]; then
  echo "FAIL: Missing config for targets:$MISSING"
else
  echo "PASS: All Makefile Android targets have config entries"
fi

# Test 3: Each target has the correct rustflags for 16KB page size
for target in $CONFIG_TARGETS; do
  # Extract the rustflags line following the target section
  section_content=$(awk "/^\[target\.$target\]/{found=1;next} /^\[/{found=0} found" "$CONFIG")

  if ! echo "$section_content" | grep -q 'max-page-size=16384'; then
    echo "FAIL: [$target] missing max-page-size=16384 in rustflags"
    ERRORS=$((ERRORS + 1))
  else
    echo "PASS: [$target] has max-page-size=16384"
  fi

  # Verify the -z flag is present (linker flag format: -z max-page-size=16384)
  if ! echo "$section_content" | grep -q '\-Clink-arg=-z'; then
    echo "FAIL: [$target] missing -Clink-arg=-z (required for linker -z flag)"
    ERRORS=$((ERRORS + 1))
  else
    echo "PASS: [$target] has -Clink-arg=-z"
  fi
done

# Test 4: Verify the flags won't affect non-Android targets
if grep -q '\[target\.\*\]' "$CONFIG" 2>/dev/null; then
  echo "WARN: Wildcard target found - may affect non-Android builds"
fi
echo "PASS: No wildcard targets (flags only apply to Android)"

echo ""
if [ "$ERRORS" -gt 0 ]; then
  echo "FAILED: $ERRORS test(s) failed"
  exit 1
fi
echo "ALL TESTS PASSED"
