# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only

load ../setup.bash

print_dot() { :; }
print_output() { :; }
format_log() { printf '%s' "${1:-}"; }
color_output() { printf '%s' "${1:-}"; }
write_log() { printf '%s\n' "${1:-}" >>"${2:-${LOG_FILE}}"; }
system_online_check() {
  [[ -z "${lATTEMPTS_LOG:-}" ]] && return 0
  [[ "$(wc -l <"${lATTEMPTS_LOG}")" -gt 1 ]]
}
restart_emulation() { return 0; }

setup() {
  setup_emba_test_env
  export LOG_PATH_MODULE="${LOG_DIR}/l25_web_checks"
  export MAX_MOD_THREADS=2
  export HTTP_RAND_REF_SIZE="NA"
  export IMAGE_NAME="test-image"
  export STATE_CHECK_MECHANISM="PING"
  mkdir -p "${LOG_PATH_MODULE}"
  # shellcheck source=modules/L25_web_checks.sh
  source "${MOD_DIR}/L25_web_checks.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "collect_web_crawl_candidates preserves variants and deduplicates exactly" {
  local lWEB_ROOT="${LOG_DIR}/web-root"
  local lEXPECTED_PATH=""
  local lWEB_URLS=()
  local -A lCRAWLED_URLS=()
  mkdir -p "${lWEB_ROOT}/z/x/a" "${lWEB_ROOT}/other"
  touch "${lWEB_ROOT}/z/x/a/index.php" "${lWEB_ROOT}/other/index.php" "${lWEB_ROOT}/bad name.php"

  collect_web_crawl_candidates "${lWEB_ROOT}" lWEB_URLS lCRAWLED_URLS

  [ "${#lWEB_URLS[@]}" -eq 5 ]
  [ "${#lCRAWLED_URLS[@]}" -eq 5 ]
  for lEXPECTED_PATH in "index.php" "a/index.php" "x/a/index.php" "z/x/a/index.php" "other/index.php"; do
    [ "${lCRAWLED_URLS[${lEXPECTED_PATH}]}" -eq 1 ]
  done
}

@test "collect_web_crawl_candidates treats associative keys literally in strict mode" {
  local lWEB_ROOT="${LOG_DIR}/strict-root"
  local lLITERAL_DIR="\$((1+1))"
  local lWEB_URLS=()
  local -A lCRAWLED_URLS=()
  mkdir -p "${lWEB_ROOT}/${lLITERAL_DIR}"
  touch "${lWEB_ROOT}/${lLITERAL_DIR}/safe.php"

  set -u
  collect_web_crawl_candidates "${lWEB_ROOT}" lWEB_URLS lCRAWLED_URLS
  set +u

  [ "${#lWEB_URLS[@]}" -eq 2 ]
  [ "${lWEB_URLS[0]}" = "safe.php" ]
  [ "${lWEB_URLS[1]}" = "${lLITERAL_DIR}/safe.php" ]
}

@test "crawl_web_urls uses a bounded worker pool and keeps response pairs" {
  local lCRAWL_LOG="${LOG_PATH_MODULE}/crawl.log"
  local lPID_LOG="${LOG_PATH_MODULE}/workers.log"
  local lWEB_URLS=(one two three four five six)
  local lUNIQUE_WORKER_COUNT=0
  lCURL_OPTS_ARR=()
  CURL_CMD_ARR=(fake_curl)

  fake_curl() {
    printf '%s\n' "${lWORKER_LOG}" >>"${lPID_LOG}"
    sleep 0.02
    printf '200:1'
  }

  crawl_web_urls "127.0.0.1" "8080" "http://127.0.0.1:8080" "${lCRAWL_LOG}" lWEB_URLS
  lUNIQUE_WORKER_COUNT="$(sort -u "${lPID_LOG}" | wc -l)"

  [ "${lUNIQUE_WORKER_COUNT}" -eq 2 ]
  [ "$(grep -c '^\[\*\] Testing ' "${lCRAWL_LOG}")" -eq 6 ]
  [ "$(grep -c '^200 OK:1$' "${lCRAWL_LOG}")" -eq 6 ]
  [ "$(wc -l <"${lCRAWL_LOG}")" -eq 12 ]
}

@test "crawl_web_urls retries connection failures after recovery" {
  local lCRAWL_LOG="${LOG_PATH_MODULE}/retry.log"
  local lATTEMPTS_LOG="${LOG_PATH_MODULE}/attempts.log"
  local lWEB_URLS=(retry-me)
  lCURL_OPTS_ARR=()
  CURL_CMD_ARR=(flaky_curl)

  flaky_curl() {
    printf 'attempt\n' >>"${lATTEMPTS_LOG}"
    if [[ "$(wc -l <"${lATTEMPTS_LOG}")" -eq 1 ]]; then
      printf '000:0'
    else
      printf '200:2'
    fi
  }
  crawl_web_urls "127.0.0.1" "8080" "http://127.0.0.1:8080" "${lCRAWL_LOG}" lWEB_URLS

  [ "$(wc -l <"${lATTEMPTS_LOG}")" -eq 2 ]
  grep -q '^000:0$' "${lCRAWL_LOG}"
  grep -q '^200 OK:2$' "${lCRAWL_LOG}"
}

@test "crawl_web_urls supports strict mode" {
  local lCRAWL_LOG="${LOG_PATH_MODULE}/strict.log"
  local lWEB_URLS=(alpha beta)
  lCURL_OPTS_ARR=()
  CURL_CMD_ARR=(strict_curl)
  strict_curl() { printf '200:3'; }

  set -euo pipefail
  crawl_web_urls "127.0.0.1" "8080" "http://127.0.0.1:8080" "${lCRAWL_LOG}" lWEB_URLS
  set +e +u
  set +o pipefail

  [ "$(grep -c '^200 OK:3$' "${lCRAWL_LOG}")" -eq 2 ]
}
