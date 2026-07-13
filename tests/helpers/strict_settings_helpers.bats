# shellcheck disable=SC1091

load ../setup

setup() {
  setup_emba_test_env
  export DEBUG_SCRIPT=0
}

teardown() {
  teardown_emba_test_env
}

@test "load_strict_mode_settings enables shell strict mode" {
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
  run load_strict_mode_settings
  [ "${status}" -eq 0 ]
}

@test "enable_strict_mode does nothing when STRICT_MODE=0" {
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
  run enable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode does nothing when STRICT_MODE=0" {
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
  run disable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode with lPRINTER=0 suppresses output" {
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
  run disable_strict_mode 1 0
  [ "${status}" -eq 0 ]
}
