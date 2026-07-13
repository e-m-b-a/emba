# shellcheck disable=SC1091

load ../setup

setup() {
  setup_emba_test_env
  export DEBUG_SCRIPT=0
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_load_strict_settings.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "load_strict_mode_settings enables shell strict mode" {
  run load_strict_mode_settings
  [ "${status}" -eq 0 ]
}

@test "enable_strict_mode does nothing when STRICT_MODE=0" {
  run enable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode does nothing when STRICT_MODE=0" {
  run disable_strict_mode 0 0
  [ "${status}" -eq 0 ]
  [[ "${output}" == "" ]]
}

@test "disable_strict_mode with lPRINTER=0 suppresses output" {
  run disable_strict_mode 1 0
  [ "${status}" -eq 0 ]
}
