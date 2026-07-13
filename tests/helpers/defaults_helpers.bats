# shellcheck disable=SC1091,SC2034

load ../setup

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_defaults.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "set_defaults sets EMBA_VERSION" {
  set_defaults
  [ -n "${EMBA_VERSION}" ]
  [ "${EMBA_VERSION}" = "2.0.2" ]
}

@test "set_defaults sets RELEASE flag" {
  set_defaults
  [ "${RELEASE}" -eq 1 ]
}

@test "set_defaults sets default log directory" {
  set_defaults
  [[ "${LOG_DIR}" == *"/logs" ]]
}

@test "set_defaults sets THREADED default" {
  set_defaults
  [ "${THREADED}" -eq 1 ]
}

@test "set_defaults sets SHORT_PATH default" {
  set_defaults
  [ "${SHORT_PATH}" -eq 0 ]
}

@test "set_defaults sets RTOS default" {
  set_defaults
  [ "${RTOS}" -eq 1 ]
}

@test "set_defaults sets ARCH_CHECK default" {
  set_defaults
  [ "${ARCH_CHECK}" -eq 1 ]
}

@test "set_defaults sets MAX_EXT_CHECK_BINS" {
  set_defaults
  [ "${MAX_EXT_CHECK_BINS}" -eq 20 ]
}

@test "set_defaults sets DEEP_EXT_DEPTH" {
  set_defaults
  [ "${DEEP_EXT_DEPTH}" -eq 4 ]
}

@test "set_defaults sets SHELLCHECK default" {
  set_defaults
  [ "${SHELLCHECK}" -eq 1 ]
}

@test "set_defaults sets SBOM_MAX_FILE_LOG" {
  set_defaults
  [ "${SBOM_MAX_FILE_LOG}" -eq 200 ]
}

@test "set_defaults sets CPE_VERSION" {
  set_defaults
  [ "${CPE_VERSION}" = "2.3" ]
}

@test "set_defaults sets SBOM_LIFECYCLE_PHASE" {
  set_defaults
  [ "${SBOM_LIFECYCLE_PHASE}" = "operations" ]
}

@test "set_log_paths sets SBOM_LOG_PATH" {
  set_log_paths
  [[ "${SBOM_LOG_PATH}" == *"/SBOM" ]]
}

@test "set_log_paths sets S02_LOG path" {
  set_log_paths
  [[ "${S02_LOG}" == *"s02_uefi_fwhunt.txt" ]]
}
