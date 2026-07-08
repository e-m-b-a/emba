#!/bin/bash -p

set -euo pipefail

cd "$(dirname "${0}")/.."

export CPE_VERSION="2.3"

eval "$(
  sed -n '/^normalize_cpe23_value()/,/^}/p' "helpers/helpers_emba_sbom_helpers.sh"
)"
eval "$(
  sed -n '/^build_cpe23_identifier()/,/^}/p' "helpers/helpers_emba_sbom_helpers.sh"
)"
eval "$(
  sed -n '/^build_cpe23_from_csv_rule()/,/^}/p' "helpers/helpers_emba_sbom_helpers.sh"
)"

eval "$(
  sed -n '/^build_cpe_identifier()/,/^}/p' "modules/S09_firmware_base_version_check.sh"
)"

failures=0

assert_cpe_field_count() {
  local cpe="${1:-}"
  local source="${2:-}"
  local fields=0

  fields="$(awk -F: '{print NF}' <<<"${cpe}")"
  if [[ "${fields}" -ne 13 ]]; then
    printf 'Invalid CPE field count (%s): %s -> %s\n' "${fields}" "${source}" "${cpe}" >&2
    failures=$((failures + 1))
  fi
}

assert_cpe_field_count "$(build_cpe_identifier ':busybox:busybox:1.36.1')" "build_cpe_identifier"
assert_cpe_field_count "$(build_cpe23_identifier 'a' 'busybox' 'busybox' '1.36.1')" "build_cpe23_identifier application"
assert_cpe_field_count "$(build_cpe23_identifier 'o' 'linux' 'linux_kernel' '4.14.336')" "build_cpe23_identifier os"
assert_cpe_field_count "$(build_cpe23_from_csv_rule 'o' ':openwrt:openwrt:18.06.2:r7676-cddd7b4c77')" "build_cpe23_from_csv_rule openwrt"
assert_cpe_field_count "$(build_cpe23_from_csv_rule 'o' ':buildroot:buildroot:2022.01.01')" "build_cpe23_from_csv_rule buildroot"

if [[ "$(build_cpe23_identifier 'a' 'busybox' 'busybox' '1.36.1')" != "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*" ]]; then
  printf 'Unexpected application CPE: %s\n' "$(build_cpe23_identifier 'a' 'busybox' 'busybox' '1.36.1')" >&2
  failures=$((failures + 1))
fi

if [[ "$(build_cpe23_identifier 'o' 'linux' 'linux_kernel' '4.14.336')" != "cpe:2.3:o:linux:linux_kernel:4.14.336:*:*:*:*:*:*:*" ]]; then
  printf 'Unexpected linux kernel CPE: %s\n' "$(build_cpe23_identifier 'o' 'linux' 'linux_kernel' '4.14.336')" >&2
  failures=$((failures + 1))
fi

if [[ "$(build_cpe23_from_csv_rule 'o' ':openwrt:openwrt:18.06.2:r7676-cddd7b4c77')" != "cpe:2.3:o:openwrt:openwrt:18.06.2:r7676-cddd7b4c77:*:*:*:*:*:*" ]]; then
  printf 'Unexpected OpenWrt CPE: %s\n' "$(build_cpe23_from_csv_rule 'o' ':openwrt:openwrt:18.06.2:r7676-cddd7b4c77')" >&2
  failures=$((failures + 1))
fi

if [[ "$(build_cpe23_from_csv_rule 'o' ':buildroot:buildroot:2022.01.01')" != "cpe:2.3:o:buildroot:buildroot:2022.01.01:*:*:*:*:*:*:*" ]]; then
  printf 'Unexpected Buildroot CPE: %s\n' "$(build_cpe23_from_csv_rule 'o' ':buildroot:buildroot:2022.01.01')" >&2
  failures=$((failures + 1))
fi

while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  line_no="${rest%%:*}"
  assignment="${rest#*:}"

  [[ "${assignment}" == *'local lCPE_IDENTIFIER="cpe:${CPE_VERSION}:${lPART}"'* ]] && continue

  template="${assignment#*\"}"
  template="${template%%\"*}"

  template="$(perl -pe 's/\$\{[^}]*\}/x/g' <<<"${template}")"

  assert_cpe_field_count "${template}" "${file}:${line_no}"
done < <(grep -R -n 'lCPE_IDENTIFIER="cpe:${CPE_VERSION}' modules helpers)

if [[ "${failures}" -gt 0 ]]; then
  exit 1
fi
