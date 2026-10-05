#!/usr/bin/env bats

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
#
# Description: Regression tests for the version identifier configuration of
#               module S09_firmware_base_version_check.
#
#               S09 reads config/bin_version_identifiers/*.json and applies the
#               grep_commands/strict_grep_commands entries to the strings output
#               of every firmware binary. Whenever a rule matches (and
#               BINARY_CORPUS_GENERATION is enabled) create_minimal_binary_corpus
#               dumps a small excerpt - the "minimal binary corpus" - to
#               tests/bin_version_testdata/<identifier>_<grep_id>.bin
#               (grep_id is the 1 based index of the grep command in the json).
#
#               These tests verify that every stored corpus file is still matched
#               by the grep identifier it was generated from. This catches
#               renamed/reordered/removed grep commands in the json config and
#               regressions in the regex itself.

# shellcheck disable=SC1091

load ../setup.bash

setup() {
  setup_emba_test_env

  export BIN_VERSION_CFG_DIR="${CONFIG_DIR}/bin_version_identifiers"
  export BIN_VERSION_TESTDATA_DIR="${INVOCATION_PATH}/tests/bin_version_testdata"

  BIN_VERSION_CFG_ARR=()
  mapfile -t BIN_VERSION_CFG_ARR < <(find "${BIN_VERSION_CFG_DIR}" -maxdepth 1 -name "*.json" | sort)

  BIN_VERSION_CORPUS_ARR=()
  mapfile -t BIN_VERSION_CORPUS_ARR < <(find "${BIN_VERSION_TESTDATA_DIR}" -maxdepth 1 -name "*.bin" | sort)
}

teardown() {
  teardown_emba_test_env
}

# splits <identifier>_<grep_id> into the rule identifier and the 1 based grep id
bvi_split_corpus_name() {
  local lBASE=""
  lBASE="$(basename "${1:-}" .bin)"

  printf '%s' "${lBASE%_*}|${lBASE##*_}"
}

# returns the json config of a rule identifier - S09 names the corpus file after
# the "identifier" json field, not after the file name, so we have to fall back
# to a reverse lookup on the identifier field
bvi_config_for_identifier() {
  local lRULE_IDENTIFIER="${1:-}"
  local lCFG_FILE=""
  local lSEARCH_RESULTS=""

  if [[ -f "${BIN_VERSION_CFG_DIR}/${lRULE_IDENTIFIER}.json" ]]; then
    printf '%s' "${BIN_VERSION_CFG_DIR}/${lRULE_IDENTIFIER}.json"
    return 0
  fi

  lSEARCH_RESULTS=$(printf '%s\0' "${BIN_VERSION_CFG_ARR[@]}" |
    xargs -0 -r jq -r --arg i "${lRULE_IDENTIFIER}" 'select(.identifier == $i) | input_filename' 2>/dev/null | sort -u)
  lCFG_FILE=$(head -n1 <<<"${lSEARCH_RESULTS}")

  [[ -z "${lCFG_FILE}" ]] && return 1
  printf '%s' "${lCFG_FILE}"
}

# returns "<json key><TAB><raw grep regex>" for the given 1 based grep id
# S09 builds the corpus only from the normal/multi_grep and the strict mode
# grep commands, therefore the lookup order is grep_commands -> strict_grep_commands
bvi_raw_grep_identifier() {
  local lCFG_FILE="${1:-}"
  local lGREP_ID="${2:-}"

  local lKEYS=("grep_commands" "strict_grep_commands")
  local lKEY=""
  local lENTRY_COUNT="0"
  local lRAW_IDENTIFIER=""

  for lKEY in "${lKEYS[@]}"; do
    lENTRY_COUNT=$(jq -r --arg k "${lKEY}" '.[$k] // [] | length' "${lCFG_FILE}" 2>/dev/null)
    [[ "${lENTRY_COUNT}" == "null" ]] && lENTRY_COUNT="0"
    if [[ "${lGREP_ID}" -le "${lENTRY_COUNT}" ]]; then
      lRAW_IDENTIFIER=$(jq -r --arg k "${lKEY}" --argjson i "$((lGREP_ID - 1))" '.[$k][$i] // empty' "${lCFG_FILE}")
      if [[ -n "${lRAW_IDENTIFIER}" ]]; then
        printf '%s\t%s' "${lKEY}" "${lRAW_IDENTIFIER}"
        return 0
      fi
    fi
  done
  return 1
}

# normalizes a raw grep identifier from the json config into the ERE fragments
# which are expected to match the corpus file - this mirrors the quoting and
# anchor handling of bin_string_checker / create_minimal_binary_corpus:
#   * the optional outer ' quoting is removed
#   * multi_grep identifiers are split on the AND marker
#   * the per fragment " quoting is removed
#   * ^ and $ are dropped, the corpus holds a context window around the match
bvi_normalize_identifier() {
  local lRAW_IDENTIFIER="${1:-}"

  local lIDENTIFIER_FULL=""
  lIDENTIFIER_FULL="${lRAW_IDENTIFIER%\'}"
  lIDENTIFIER_FULL="${lIDENTIFIER_FULL#\'}"

  local lIDENTIFIER_FRAGMENT=""
  while IFS= read -r lIDENTIFIER_FRAGMENT; do
    lIDENTIFIER_FRAGMENT="${lIDENTIFIER_FRAGMENT//\"/}"
    lIDENTIFIER_FRAGMENT="${lIDENTIFIER_FRAGMENT//[\^\$]/}"
    [[ -z "${lIDENTIFIER_FRAGMENT}" ]] && continue
    printf '%s\n' "${lIDENTIFIER_FRAGMENT}"
  done < <(printf '%s\n' "${lIDENTIFIER_FULL//AND/$'\n'}")
}

# dumps "<config name><TAB><raw grep regex>" for every grep command which is
# applied by S09 in static mode (normal/multi_grep and strict)
bvi_all_static_identifiers() {
  printf '%s\0' "${BIN_VERSION_CFG_ARR[@]}" |
    xargs -0 -r jq -r '(.identifier // input_filename) as $i | ((.grep_commands // [])[] | [$i, .]), ((.strict_grep_commands // [])[] | [$i, .]) | @tsv' \
      2>/dev/null
}

# dumps one TSV line per static rule which S09 could apply:
# <corpus key>\t<identifier>\t<grep id>\t<json key>\t<parsing modes>\t<raw grep regex>
# the corpus key is exactly the file name create_minimal_binary_corpus generates
# note: join("\t") instead of @tsv - @tsv would escape the backslashes of the regex
bvi_static_rules() {
  printf '%s\0' "${BIN_VERSION_CFG_ARR[@]}" |
    xargs -0 -r jq -r '(.identifier // input_filename) as $id
                       | ((.parsing_mode // []) | join(",")) as $mode
                       | [ ((.grep_commands // [])       | to_entries[] | [.value, ((.key + 1) | tostring), "grep_commands"]),
                           ((.strict_grep_commands // []) | to_entries[] | [.value, ((.key + 1) | tostring), "strict_grep_commands"]) ]
                       | .[]
                       | [($id + "_" + .[1] + ".bin"), $id, .[1], .[2], $mode, .[0]]
                       | join("\t")' \
      2>/dev/null
}

@test "bin_version_testdata corpus directory is present and not empty" {
  [ -d "${BIN_VERSION_TESTDATA_DIR}" ]
  [ "${#BIN_VERSION_CORPUS_ARR[@]}" -gt 0 ]
}

@test "every bin_version_testdata file is referenced by an existing json config" {
  local lFAILURES=""

  local lCORPUS_FILE=""
  local lRULE_IDENTIFIER=""
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lRULE_IDENTIFIER="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    lRULE_IDENTIFIER="${lRULE_IDENTIFIER%%|*}"
    if ! run bvi_config_for_identifier "${lRULE_IDENTIFIER}"; then
      lFAILURES+="no json config for rule identifier ${lRULE_IDENTIFIER} (corpus: $(basename "${lCORPUS_FILE}"))
"
      continue
    fi
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "every bin_version_testdata grep id points to an existing grep command" {
  local lFAILURES=""

  local lCORPUS_FILE=""
  local lBASE=""
  local lRULE_IDENTIFIER=""
  local lGREP_ID=""
  local lCFG_FILE=""
  local lRESOLVED=""
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lBASE="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    lRULE_IDENTIFIER="${lBASE%%|*}"
    lGREP_ID="${lBASE##*|}"

    if ! [[ "${lGREP_ID}" =~ ^[0-9]+$ ]] || [[ "${lGREP_ID}" -lt 1 ]]; then
      lFAILURES+="corpus $(basename "${lCORPUS_FILE}") has an invalid grep id '${lGREP_ID}'
"
      continue
    fi
    if ! lCFG_FILE="$(bvi_config_for_identifier "${lRULE_IDENTIFIER}")"; then
      continue
    fi
    if ! lRESOLVED="$(bvi_raw_grep_identifier "${lCFG_FILE}" "${lGREP_ID}")"; then
      lFAILURES+="corpus $(basename "${lCORPUS_FILE}") -> ${lRULE_IDENTIFIER}.json has no grep command with id ${lGREP_ID}
"
    fi
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "corpus grep ids match the identifier field of their json config" {
  local lFAILURES=""

  local lCORPUS_FILE=""
  local lRULE_IDENTIFIER=""
  local lCFG_FILE=""
  local lJSON_IDENTIFIER=""
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lRULE_IDENTIFIER="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    lRULE_IDENTIFIER="${lRULE_IDENTIFIER%%|*}"
    if ! lCFG_FILE="$(bvi_config_for_identifier "${lRULE_IDENTIFIER}")"; then
      continue
    fi
    lJSON_IDENTIFIER=$(jq -r .identifier "${lCFG_FILE}")
    if [[ "${lJSON_IDENTIFIER}" != "${lRULE_IDENTIFIER}" ]]; then
      lFAILURES+="corpus $(basename "${lCORPUS_FILE}") resolved to ${lCFG_FILE} with identifier '${lJSON_IDENTIFIER}'
"
    fi
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "every corpus file is matched by its configured grep identifier" {
  local lFAILURES=""

  local lCORPUS_FILE=""
  local lBASE=""
  local lGREP_ID=""
  local lCFG_FILE=""
  local lRESOLVED=""
  local lGREP_KEY=""
  local lRAW_IDENTIFIER=""
  local lFRAGMENT=""
  local lFRAGMENTS=()
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lBASE="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    lGREP_ID="${lBASE##*|}"

    if ! lCFG_FILE="$(bvi_config_for_identifier "${lBASE%%|*}")"; then
      continue
    fi
    if ! lRESOLVED="$(bvi_raw_grep_identifier "${lCFG_FILE}" "${lGREP_ID}")"; then
      continue
    fi
    lGREP_KEY="${lRESOLVED%%$'\t'*}"
    lRAW_IDENTIFIER="${lRESOLVED#*$'\t'}"

    mapfile -t lFRAGMENTS < <(bvi_normalize_identifier "${lRAW_IDENTIFIER}")
    if [[ "${#lFRAGMENTS[@]}" -eq 0 ]]; then
      lFAILURES+="$(basename "${lCORPUS_FILE}") -> ${lGREP_KEY}[${lGREP_ID}] has no usable grep regex
"
      continue
    fi

    for lFRAGMENT in "${lFRAGMENTS[@]}"; do
      if ! grep -q -a -o -E -- "${lFRAGMENT}" "${lCORPUS_FILE}"; then
        lFAILURES+="$(basename "${lCORPUS_FILE}") -> ${lGREP_KEY}[${lGREP_ID}] regex '${lFRAGMENT}' does not match the corpus
"
      fi
    done
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "every corpus file is not empty and is handled as binary by grep" {
  local lCORPUS_FILE=""
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    [ -s "${lCORPUS_FILE}" ] || {
      echo "[*] empty corpus file: ${lCORPUS_FILE}" >&2
      false
    }
    grep -q -a -E "." "${lCORPUS_FILE}" || {
      echo "[*] corpus file without any data: ${lCORPUS_FILE}" >&2
      false
    }
  done
}

@test "all grep identifiers used by the corpus are valid extended regexes" {
  local lFAILURES=""

  local lCORPUS_FILE=""
  local lBASE=""
  local lCFG_FILE=""
  local lRESOLVED=""
  local lFRAGMENT=""
  local lFRAGMENTS=()
  local lGREP_RC=0
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lBASE="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    if ! lCFG_FILE="$(bvi_config_for_identifier "${lBASE%%|*}")"; then
      continue
    fi
    if ! lRESOLVED="$(bvi_raw_grep_identifier "${lCFG_FILE}" "${lBASE##*|}")"; then
      continue
    fi

    mapfile -t lFRAGMENTS < <(bvi_normalize_identifier "${lRESOLVED#*$'\t'}")
    for lFRAGMENT in "${lFRAGMENTS[@]}"; do
      lGREP_RC=0
      printf '' | grep -a -E -- "${lFRAGMENT}" >/dev/null 2>&1 || lGREP_RC=$?
      if [[ "${lGREP_RC}" -eq 2 ]]; then
        lFAILURES+="$(basename "${lCORPUS_FILE}") has an invalid ERE: '${lFRAGMENT}'
"
      fi
    done
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "multi_grep identifiers require all AND separated fragments in the corpus" {
  local lFAILURES=""
  local lCHECKED=0

  local lCORPUS_FILE=""
  local lBASE=""
  local lCFG_FILE=""
  local lRESOLVED=""
  local lRAW_IDENTIFIER=""
  local lFRAGMENT=""
  local lFRAGMENTS=()
  for lCORPUS_FILE in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    lBASE="$(bvi_split_corpus_name "${lCORPUS_FILE}")"
    if ! lCFG_FILE="$(bvi_config_for_identifier "${lBASE%%|*}")"; then
      continue
    fi
    if ! lRESOLVED="$(bvi_raw_grep_identifier "${lCFG_FILE}" "${lBASE##*|}")"; then
      continue
    fi
    lRAW_IDENTIFIER="${lRESOLVED#*$'\t'}"
    [[ "${lRAW_IDENTIFIER}" == *AND* ]] || continue

    lCHECKED=$((lCHECKED + 1))
    mapfile -t lFRAGMENTS < <(bvi_normalize_identifier "${lRAW_IDENTIFIER}")
    if [[ "${#lFRAGMENTS[@]}" -lt 2 ]]; then
      lFAILURES+="$(basename "${lCORPUS_FILE}") multi_grep identifier was not split into multiple fragments
"
      continue
    fi
    for lFRAGMENT in "${lFRAGMENTS[@]}"; do
      if ! grep -q -a -o -E -- "${lFRAGMENT}" "${lCORPUS_FILE}"; then
        lFAILURES+="$(basename "${lCORPUS_FILE}") is missing multi_grep fragment '${lFRAGMENT}'
"
      fi
    done
  done

  [ "${lCHECKED}" -gt 0 ] || echo "[*] no multi_grep corpus files available - test is a no-op" >&2
  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "corpus regexes do not match unrelated placeholder content" {
  local lDECOY_FILE="${LOG_DIR}/bvi_decoy_corpus.bin"
  printf '%s\n' "EMBA_CORPUS_TEST_DECOY generic placeholder without any version information" >"${lDECOY_FILE}"

  local lFAILURES=""
  local lCFG_NAME=""
  local lRAW_IDENTIFIER=""
  local lFRAGMENT=""
  local lFRAGMENTS=()

  while IFS=$'\t' read -r lCFG_NAME lRAW_IDENTIFIER; do
    [[ -z "${lRAW_IDENTIFIER}" ]] && continue
    mapfile -t lFRAGMENTS < <(bvi_normalize_identifier "${lRAW_IDENTIFIER}")
    for lFRAGMENT in "${lFRAGMENTS[@]}"; do
      if grep -q -a -o -E -- "${lFRAGMENT}" "${lDECOY_FILE}"; then
        lFAILURES+="${lCFG_NAME} regex '${lFRAGMENT}' matches placeholder content
"
      fi
    done
  done < <(bvi_all_static_identifiers)

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "bin_version_identifiers configs are valid json and provide the mandatory fields" {
  local lFAILURES=""

  local lCFG_FILE=""
  local lBASENAME=""
  local lCHECK_RESULT=""
  local lJSON_IDENTIFIER=""
  local lPARSING_MODE=""
  local lVENDOR_COUNT="0"
  local lPRODUCT_COUNT="0"
  local lLICENSE_COUNT="0"
  local lEXTRACTION_COUNT="0"
  local lGREP_COUNT="0"
  local lSTRICT_GREP_COUNT="0"
  local lENTRY=""
  for lCFG_FILE in "${BIN_VERSION_CFG_ARR[@]}"; do
    lBASENAME="$(basename "${lCFG_FILE}" .json)"

    # a single jq pass per config keeps this test fast:
    # identifier|parsing_mode|vendor|product|license|extraction|grep|strict_grep
    lCHECK_RESULT=$(jq -r '[(.identifier // "null"),
                           ((.parsing_mode // []) | join(" ")),
                           ((.vendor_names // []) | length),
                           ((.product_names // []) | length),
                           ((.licenses // []) | length),
                           ((.version_extraction // []) | length),
                           ((.grep_commands // []) | length),
                           ((.strict_grep_commands // []) | length)] | join("|")' "${lCFG_FILE}" 2>/dev/null)
    if [[ -z "${lCHECK_RESULT}" ]]; then
      lFAILURES+="${lBASENAME}.json is not valid json
"
      continue
    fi

    IFS='|' read -r lJSON_IDENTIFIER lPARSING_MODE lVENDOR_COUNT lPRODUCT_COUNT \
      lLICENSE_COUNT lEXTRACTION_COUNT lGREP_COUNT lSTRICT_GREP_COUNT <<<"${lCHECK_RESULT}"

    if [[ "${lJSON_IDENTIFIER}" == "null" || -z "${lJSON_IDENTIFIER}" ]]; then
      lFAILURES+="${lBASENAME}.json has no identifier
"
    fi

    if [[ -z "${lPARSING_MODE}" ]]; then
      lFAILURES+="${lBASENAME}.json has no parsing_mode entry
"
    fi

    for lENTRY in "vendor_names:${lVENDOR_COUNT}" "product_names:${lPRODUCT_COUNT}" \
      "licenses:${lLICENSE_COUNT}" "version_extraction:${lEXTRACTION_COUNT}"; do
      if [[ "${lENTRY##*:}" == "0" ]]; then
        lFAILURES+="${lBASENAME}.json has an empty ${lENTRY%%:*} list
"
      fi
    done

    # normal/multi_grep rules are applied to the json grep_commands
    if [[ "${lPARSING_MODE}" == *"normal"* || "${lPARSING_MODE}" == *"multi_grep"* ]]; then
      if [[ "${lGREP_COUNT}" == "0" ]]; then
        lFAILURES+="${lBASENAME}.json is used in normal/multi_grep mode but has no grep_commands
"
      fi
    fi

    # strict rules are applied to the json strict_grep_commands
    if [[ "${lPARSING_MODE}" == *"strict"* ]]; then
      if [[ "${lSTRICT_GREP_COUNT}" == "0" ]]; then
        lFAILURES+="${lBASENAME}.json is used in strict mode but has no strict_grep_commands
"
      fi
    fi
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "strict mode rules provide affected_paths and every parsing_mode is known" {
  local lFAILURES=""
  local lALLOWED_MODES=" normal live multi_grep strict zgrep no_static emulation_only "

  local lCFG_FILE=""
  local lBASENAME=""
  local lMODE=""
  local lMODE_ENTRY=""
  local lMODE_COUNT=0
  local lPATH_COUNT=0
  for lCFG_FILE in "${BIN_VERSION_CFG_ARR[@]}"; do
    lBASENAME="$(basename "${lCFG_FILE}" .json)"
    lMODE_COUNT=0

    # one jq pass: affected_paths count|space separated parsing modes
    while IFS='|' read -r lPATH_COUNT lMODE; do
      [[ -z "${lPATH_COUNT}" ]] && lPATH_COUNT="0"
      for lMODE_ENTRY in ${lMODE}; do
        [[ -z "${lMODE_ENTRY}" ]] && continue
        if [[ "${lALLOWED_MODES}" != *" ${lMODE_ENTRY} "* ]]; then
          lFAILURES+="${lBASENAME}.json has an unknown parsing_mode '${lMODE_ENTRY}'
"
        fi
        if [[ "${lMODE_ENTRY}" == "strict" ]]; then
          lMODE_COUNT=$((lMODE_COUNT + 1))
        fi
      done
      if [[ "${lMODE_COUNT}" -gt 0 && "${lPATH_COUNT}" == "0" ]]; then
        lFAILURES+="${lBASENAME}.json is used in strict mode but has no affected_paths
"
        lMODE_COUNT=0
      fi
    done < <(jq -r '[(.affected_paths // []) | length] + [(.parsing_mode // []) | join(" ")] | join("|")' \
      "${lCFG_FILE}" 2>/dev/null)
  done

  [ -z "${lFAILURES}" ] || {
    printf '%s' "${lFAILURES}" >&2
    false
  }
}

@test "bvi_normalize_identifier splits multi_grep identifiers and drops quoting and anchors" {
  local lRAW_IDENTIFIER=""
  printf -v lRAW_IDENTIFIER '%s%s%s' "'" '"^smbd version %s started.$"AND"^[2-5]\.[0-9]+\.[0-9]+$"' "'"

  run bvi_normalize_identifier "${lRAW_IDENTIFIER}"
  [ "${status}" -eq 0 ]
  [ "${#lines[@]}" -eq 2 ]
  [ "${lines[0]}" = "smbd version %s started." ]
  [ "${lines[1]}" = "[2-5]\.[0-9]+\.[0-9]+" ]
}

@test "bvi_normalize_identifier keeps single grep identifiers untouched" {
  run bvi_normalize_identifier 'hostapd\ v[0-9](\.[0-9]+)+(-devel)?$'
  [ "${status}" -eq 0 ]
  [ "${#lines[@]}" -eq 1 ]
  [ "${lines[0]}" = "hostapd\ v[0-9](\.[0-9]+)+(-devel)?" ]
}

@test "bvi_split_corpus_name separates rule identifier and grep id" {
  run bvi_split_corpus_name "/tmp/anything/busybox_3.bin"
  [ "${status}" -eq 0 ]
  [ "${output}" = "busybox|3" ]
}

@test "bvi_raw_grep_identifier resolves the corpus grep id against the json" {
  local lCFG_FILE=""
  lCFG_FILE="$(bvi_config_for_identifier "busybox")"

  run bvi_raw_grep_identifier "${lCFG_FILE}" "2"
  [ "${status}" -eq 0 ]
  [[ "${output}" == grep_commands$'\t'* ]]

  run bvi_raw_grep_identifier "${lCFG_FILE}" "99"
  [ "${status}" -ne 0 ]
}

@test "bvi_config_for_identifier resolves configs via the identifier field" {
  run bvi_config_for_identifier "musl_libc"
  [ "${status}" -eq 0 ]
  [[ "${output}" == */musl_libc.json ]]

  run bvi_config_for_identifier "busybox"
  [ "${status}" -eq 0 ]
  [[ "${output}" == */busybox.json ]]

  run bvi_config_for_identifier "definitely_no_such_identifier_1234"
  [ "${status}" -ne 0 ]
}

@test "testdata coverage report - how many static rules are matched and how many are missing" {
  # a corpus file is named <identifier>_<grep id>.bin - for a rule which exists in
  # grep_commands *and* in strict_grep_commands the same corpus key is used by
  # both modes, therefore the report works on the distinct corpus keys
  local lENTRY_TOTAL="0"
  local lKEY_TOTAL="0"
  local lKEY_MATCHED="0"
  local lKEY_STALE="0"
  local lKEY_MISSING="0"
  local lORPHAN_TOTAL="0"

  local lCORPUS_KEY=""
  local lRULE_IDENTIFIER=""
  local lGREP_ID=""
  local lJSON_KEY=""
  local lPARSING_MODE=""
  local lRAW_IDENTIFIER=""
  local lCORPUS_FILE=""
  local lFRAGMENT=""
  local lFRAGMENTS=()
  local lRULE_MATCHES="1"

  local lGC_TOTAL="0"
  local lGC_MATCHED="0"
  local lSG_TOTAL="0"
  local lSG_MATCHED="0"
  local lID_FULL="0"
  local lID_PARTIAL="0"
  local lID_NONE="0"
  local lID_NAMES=""
  local lFULL_ID_NAMES=""
  local lPARTIAL_ID_NAMES=""
  local lSTALE_ID_NAMES=""
  local lORPHAN_NAMES=""

  declare -A lRULE_ARR=()
  declare -A lID_TOTAL_ARR=()
  declare -A lID_MATCHED_ARR=()
  declare -A lID_STALE_ARR=()

  # 1st pass: collect the static rules - a second entry for an already known
  # corpus key (grep_commands vs strict_grep_commands) is only a rule entry
  while IFS=$'\t' read -r lCORPUS_KEY lRULE_IDENTIFIER lGREP_ID lJSON_KEY lPARSING_MODE lRAW_IDENTIFIER; do
    [[ -z "${lCORPUS_KEY}" ]] && continue
    lENTRY_TOTAL=$((lENTRY_TOTAL + 1))
    [[ -n "${lRULE_ARR[${lCORPUS_KEY}]:-}" ]] && continue
    lRULE_ARR[${lCORPUS_KEY}]="${lJSON_KEY}|${lRAW_IDENTIFIER}"
    lKEY_TOTAL=$((lKEY_TOTAL + 1))
  done < <(bvi_static_rules)

  # 2nd pass: classify every distinct corpus key
  for lCORPUS_KEY in "${!lRULE_ARR[@]}"; do
    lJSON_KEY="${lRULE_ARR[${lCORPUS_KEY}]%%|*}"
    lRAW_IDENTIFIER="${lRULE_ARR[${lCORPUS_KEY}]#*|}"
    lRULE_IDENTIFIER="${lCORPUS_KEY%_*}"

    lID_TOTAL_ARR[${lRULE_IDENTIFIER}]=$((${lID_TOTAL_ARR[${lRULE_IDENTIFIER}]:-0} + 1))
    if [[ "${lJSON_KEY}" == "grep_commands" ]]; then
      lGC_TOTAL=$((lGC_TOTAL + 1))
    else
      lSG_TOTAL=$((lSG_TOTAL + 1))
    fi

    lCORPUS_FILE="${BIN_VERSION_TESTDATA_DIR}/${lCORPUS_KEY}"
    if [[ ! -f "${lCORPUS_FILE}" ]]; then
      lKEY_MISSING=$((lKEY_MISSING + 1))
      continue
    fi

    # the corpus is present - does the configured regex still match it?
    lRULE_MATCHES=1
    mapfile -t lFRAGMENTS < <(bvi_normalize_identifier "${lRAW_IDENTIFIER}")
    for lFRAGMENT in "${lFRAGMENTS[@]}"; do
      if ! grep -q -a -o -E -- "${lFRAGMENT}" "${lCORPUS_FILE}"; then
        lRULE_MATCHES=0
        break
      fi
    done

    if [[ "${lRULE_MATCHES}" -eq 1 ]]; then
      lKEY_MATCHED=$((lKEY_MATCHED + 1))
      lID_MATCHED_ARR[${lRULE_IDENTIFIER}]=$((${lID_MATCHED_ARR[${lRULE_IDENTIFIER}]:-0} + 1))
      if [[ "${lJSON_KEY}" == "grep_commands" ]]; then
        lGC_MATCHED=$((lGC_MATCHED + 1))
      else
        lSG_MATCHED=$((lSG_MATCHED + 1))
      fi
    else
      lKEY_STALE=$((lKEY_STALE + 1))
      lID_STALE_ARR[${lRULE_IDENTIFIER}]=$((${lID_STALE_ARR[${lRULE_IDENTIFIER}]:-0} + 1))
      lSTALE_ID_NAMES+="${lRULE_IDENTIFIER} "
    fi
  done

  # 3rd pass: rule coverage per identifier
  for lRULE_IDENTIFIER in "${!lID_TOTAL_ARR[@]}"; do
    lID_MATCHED_ARR[${lRULE_IDENTIFIER}]="${lID_MATCHED_ARR[${lRULE_IDENTIFIER}]:-0}"
    lID_STALE_ARR[${lRULE_IDENTIFIER}]="${lID_STALE_ARR[${lRULE_IDENTIFIER}]:-0}"
    lID_NAMES+="${lRULE_IDENTIFIER} "
    if [[ "${lID_MATCHED_ARR[${lRULE_IDENTIFIER}]}" -eq 0 ]]; then
      lID_NONE=$((lID_NONE + 1))
    elif [[ "${lID_MATCHED_ARR[${lRULE_IDENTIFIER}]}" -eq "${lID_TOTAL_ARR[${lRULE_IDENTIFIER}]}" ]]; then
      lID_FULL=$((lID_FULL + 1))
      lFULL_ID_NAMES+="${lRULE_IDENTIFIER} "
    else
      lID_PARTIAL=$((lID_PARTIAL + 1))
      lPARTIAL_ID_NAMES+="${lRULE_IDENTIFIER}(${lID_MATCHED_ARR[${lRULE_IDENTIFIER}]}/${lID_TOTAL_ARR[${lRULE_IDENTIFIER}]}) "
    fi
  done

  # 4th pass: corpus files which do not belong to any static rule
  local lCORPUS_FILE_FOUND=""
  for lCORPUS_FILE_FOUND in "${BIN_VERSION_CORPUS_ARR[@]}"; do
    if [[ -z "${lRULE_ARR[$(basename "${lCORPUS_FILE_FOUND}")]:-}" ]]; then
      lORPHAN_TOTAL=$((lORPHAN_TOTAL + 1))
      lORPHAN_NAMES+="$(basename "${lCORPUS_FILE_FOUND}") "
    fi
  done

  echo "[*] S09 static rule coverage of tests/bin_version_testdata"
  echo "    grep entries in config (grep_commands + strict_grep_commands) : ${lENTRY_TOTAL}"
  echo "    distinct corpus keys (identifier + grep id)                   : ${lKEY_TOTAL}"
  echo "    matched by a testdata corpus file                             : ${lKEY_MATCHED}"
  echo "    corpus file present but regex no longer matches               : ${lKEY_STALE}"
  echo "    without any testdata corpus file                              : ${lKEY_MISSING}"
  echo "    testdata corpus files without a matching rule                 : ${lORPHAN_TOTAL}"
  echo "    grep_commands        : ${lGC_MATCHED}/${lGC_TOTAL} covered"
  echo "    strict_grep_commands : ${lSG_MATCHED}/${lSG_TOTAL} covered"
  echo "    identifiers fully covered      : ${lID_FULL}/${#lID_TOTAL_ARR[@]}"
  echo "    identifiers partially covered  : ${lID_PARTIAL}/${#lID_TOTAL_ARR[@]}"
  echo "    identifiers without coverage   : ${lID_NONE}/${#lID_TOTAL_ARR[@]}"
  echo "    fully covered identifiers      :${lFULL_ID_NAMES}"
  echo "    partially covered identifiers  :${lPARTIAL_ID_NAMES}"
  [[ -z "${lSTALE_ID_NAMES}" ]] || echo "    identifiers with stale corpus   :${lSTALE_ID_NAMES}"
  [[ -z "${lORPHAN_NAMES}" ]] || echo "    orphaned testdata corpus files  :${lORPHAN_NAMES}"

  [ "${lKEY_TOTAL}" -gt 0 ]
  [[ $((lKEY_MATCHED + lKEY_STALE + lKEY_MISSING)) -eq "${lKEY_TOTAL}" ]]
  [[ $((lID_FULL + lID_PARTIAL + lID_NONE)) -eq "${#lID_TOTAL_ARR[@]}" ]]
  [ "${#BIN_VERSION_CORPUS_ARR[@]}" -eq $((lKEY_MATCHED + lKEY_STALE + lORPHAN_TOTAL)) ]
  [ "${lKEY_STALE}" -eq 0 ]
  [ "${lORPHAN_TOTAL}" -eq 0 ]
}
