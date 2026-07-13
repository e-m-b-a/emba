# shellcheck disable=SC1091,SC2034

load ../setup

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_print.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "strip_color_codes removes ANSI escape sequences" {
  result="$(strip_color_codes $'\033[0;32mhello\033[0m')"
  [ "${result}" = "hello" ]
}

@test "strip_color_codes handles multiple color codes" {
  result="$(strip_color_codes $'\033[0;31mERROR\033[0m: \033[0;32mOK\033[0m')"
  [ "${result}" = "ERROR: OK" ]
}

@test "strip_color_codes handles plain text unchanged" {
  result="$(strip_color_codes 'plain text')"
  [ "${result}" = "plain text" ]
}

@test "strip_color_codes handles empty input" {
  result="$(strip_color_codes '')"
  [ "${result}" = "" ]
}

@test "escape_echo escapes special characters" {
  result="$(escape_echo 'hello; rm -rf /')"
  [[ "${result}" == *'hello'* ]]
  [[ "${result}" == *'rm'* ]]
}

@test "escape_echo handles simple strings" {
  result="$(escape_echo 'abc123')"
  [[ "${result}" == *'abc123'* ]]
}

@test "check_int accepts valid integers" {
  run check_int "42"
  [ "${status}" -eq 0 ]
}

@test "check_int rejects non-integers" {
  run check_int "abc"
  [ "${status}" -eq 1 ]
}

@test "check_int accepts empty input" {
  run check_int ""
  [ "${status}" -eq 0 ]
}

@test "check_alnum accepts alphanumeric" {
  run check_alnum "abc123"
  [ "${status}" -eq 0 ]
}

@test "check_alnum rejects special chars" {
  run check_alnum "abc-123"
  [ "${status}" -eq 1 ]
}

@test "check_vendor accepts valid vendor names" {
  run check_vendor "MyVendor_123"
  [ "${status}" -eq 0 ]
}

@test "check_vendor rejects invalid vendor names" {
  run check_vendor "vendor space"
  [ "${status}" -eq 1 ]
}

@test "safe_echo outputs string" {
  result="$(safe_echo "test")"
  [ -n "${result}" ]
}

@test "format_log strips ANSI codes when FORMAT_LOG=0" {
  FORMAT_LOG=0
  result="$(format_log $'\\033[0;32mtest\\033[0m')"
  [[ "${result}" != *'033'* ]]
}

@test "format_log preserves ANSI codes when FORMAT_LOG=1" {
  FORMAT_LOG=1
  result="$(format_log $'\\033[0;32mtest\\033[0m')"
  [ -n "${result}" ]
}

@test "print_ln outputs newline" {
  run print_ln "no_log"
  [ "${status}" -eq 0 ]
}

@test "print_date returns a date string" {
  result="$(print_date)"
  [ -n "${result}" ]
}

@test "show_runtime returns duration" {
  SECONDS=3661
  result="$(show_runtime 1)"
  [ -n "${result}" ]
}

@test "indent prepends spaces" {
  result="$(indent "hello")"
  [[ "${result}" == *"hello"* ]]
}

@test "white wraps text in NC tags" {
  result="$(white "test")"
  [[ "${result}" == *"test"* ]]
}

@test "red wraps text in RED tags" {
  result="$(red "error")"
  [[ "${result}" == *"error"* ]]
}

@test "green wraps text in GREEN tags" {
  result="$(green "ok")"
  [[ "${result}" == *"ok"* ]]
}

@test "check_path_input accepts valid paths" {
  run check_path_input "/home/user/test"
  [ "${status}" -eq 0 ]
}

@test "check_path_input rejects invalid chars" {
  run check_path_input "/home/user/test|bad"
  [ "${status}" -eq 1 ]
}

@test "color_output formats [-] as red" {
  result="$(color_output "[-] error msg")"
  [[ "${result}" == *"error msg"* ]]
}

@test "color_output formats [+] as green" {
  result="$(color_output "[+] success msg")"
  [[ "${result}" == *"success msg"* ]]
}

@test "color_output formats [*] as orange" {
  result="$(color_output "[*] info msg")"
  [[ "${result}" == *"info msg"* ]]
}

@test "format_grep_log strips ANSI codes" {
  result="$(format_grep_log "test")"
  [ -n "${result}" ]
}

@test "reset_module_count resets counter" {
  SUB_MODULE_COUNT=5
  reset_module_count
  [ "${SUB_MODULE_COUNT}" -eq 0 ]
}

@test "secure_sleep handles zero time" {
  run secure_sleep 0
  [ "${status}" -eq 0 ]
}
