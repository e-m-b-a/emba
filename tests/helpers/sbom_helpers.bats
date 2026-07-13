# shellcheck disable=SC1091

load ../setup

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_print.sh"
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_sbom_helpers.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "build_purl_identifier builds basic purl" {
  result="$(build_purl_identifier "NA" "deb" "curl" "7.68.0" "")"
  [ "${result}" = "pkg:deb/generic/curl@7.68.0" ]
}

@test "build_purl_identifier includes arch" {
  result="$(build_purl_identifier "NA" "deb" "curl" "7.68.0" "amd64")"
  [[ "${result}" == *"?arch=amd64"* ]]
}

@test "build_purl_identifier handles no version" {
  result="$(build_purl_identifier "NA" "deb" "curl" "" "")"
  [ "${result}" = "pkg:deb/generic/curl" ]
}

@test "build_purl_identifier replaces spaces in arch" {
  result="$(build_purl_identifier "NA" "deb" "curl" "1.0" "mips 32")"
  [[ "${result}" == *"?arch=mips-32"* ]]
}

@test "build_purl_identifier includes distro for non-generic" {
  result="$(build_purl_identifier "ubuntu" "deb" "curl" "7.68.0" "")"
  [[ "${result}" == *"distro=ubuntu"* ]]
}

@test "build_purl_identifier handles -based distro" {
  result="$(build_purl_identifier "debian-based" "deb" "curl" "7.0" "")"
  [[ "${result}" != *"distro"* ]]
}

@test "build_purl_identifier purl has correct prefix" {
  result="$(build_purl_identifier "ubuntu" "deb" "bash" "5.0" "amd64")"
  [[ "${result}" == "pkg:deb/ubuntu/bash@5.0?arch=amd64&distro=ubuntu" ]]
}

@test "get_confidence_string maps 1 to very-low" {
  result="$(get_confidence_string 1)"
  [ "${result}" = "very-low" ]
}

@test "get_confidence_string maps 2 to low" {
  result="$(get_confidence_string 2)"
  [ "${result}" = "low" ]
}

@test "get_confidence_string maps 3 to medium" {
  result="$(get_confidence_string 3)"
  [ "${result}" = "medium" ]
}

@test "get_confidence_string maps 4 to high" {
  result="$(get_confidence_string 4)"
  [ "${result}" = "high" ]
}

@test "get_confidence_string returns NA for unknown" {
  result="$(get_confidence_string 99)"
  [ "${result}" = "NA" ]
}

@test "get_confidence_string defaults to medium for empty input" {
  result="$(get_confidence_string "")"
  [ "${result}" = "medium" ]
}

@test "get_confidence_value maps very-low to 1" {
  result="$(get_confidence_value "very-low")"
  [ "${result}" = "1" ]
}

@test "get_confidence_value maps low to 2" {
  result="$(get_confidence_value "low")"
  [ "${result}" = "2" ]
}

@test "get_confidence_value maps medium to 3" {
  result="$(get_confidence_value "medium")"
  [ "${result}" = "3" ]
}

@test "get_confidence_value maps high to 4" {
  result="$(get_confidence_value "high")"
  [ "${result}" = "4" ]
}

@test "get_confidence_value returns 99 for unknown" {
  result="$(get_confidence_value "critical")"
  [ "${result}" = "99" ]
}

@test "get_confidence_value returns 99 for empty input" {
  result="$(get_confidence_value "")"
  [ "${result}" = "99" ]
}

@test "validate_xml rejects DOCTYPE" {
  local lXML="${LOG_DIR}/test.xml"
  echo '<!DOCTYPE foo>' >"${lXML}"
  run validate_xml "${lXML}"
  [ "${status}" -eq 1 ]
}

@test "validate_xml rejects ENTITY" {
  local lXML="${LOG_DIR}/test.xml"
  echo '<!ENTITY foo>' >"${lXML}"
  run validate_xml "${lXML}"
  [ "${status}" -eq 1 ]
}

@test "validate_xml accepts clean xml" {
  local lXML="${LOG_DIR}/test.xml"
  echo '<root><item/></root>' >"${lXML}"
  run validate_xml "${lXML}"
  [ "${status}" -eq 0 ]
}

@test "validate_xml handles missing file" {
  run validate_xml "${LOG_DIR}/nonexistent.xml"
  [ "${status}" -eq 0 ]
}
