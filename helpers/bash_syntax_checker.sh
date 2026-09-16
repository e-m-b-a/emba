#!/bin/bash -p

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
# Author(s): Michael Messner

# Description: Checks all EMBA source files with bash -n for syntax errors
#

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # no color

EMBA_SOURCES_ARR=()
EMBA_SOURCE_FILE=""
MODULES_TO_CHECK_ARR=()

import_emba_scripts() {
  local lFILES_ARR=()
  local lEMBA_FILE=""

  mapfile -t lFILES_ARR < <(find ./ \( -name .git -o -name external -o -path "./tests/bats-core" \) -prune -o -type f -print 2>/dev/null)
  for lEMBA_FILE in "${lFILES_ARR[@]}"; do
    if [[ "${lEMBA_FILE}" == ./tests/* ]] && [[ "${lEMBA_FILE}" == *.bats ]]; then
      echo "${lEMBA_FILE}"
      EMBA_SOURCES_ARR+=("${lEMBA_FILE}")
      continue
    fi
    if file "${lEMBA_FILE}" | grep -q "shell script"; then
      echo "${lEMBA_FILE}"
      EMBA_SOURCES_ARR+=("${lEMBA_FILE}")
    fi
  done
}

check_bats_syntax() {
  # Transform a bats test file into plain bash so we can validate it with
  # `bash -n` without requiring a bats runtime.  The main trick is replacing
  # bats-specific `@test "name" { ... }` declarations with ordinary bash
  # function declarations, since `bash -n` has no idea what `@test` means.
  #
  # We run the whole transform + validation inside a subshell ( ... ) so
  # the temp file is cleaned up automatically via an EXIT trap and no state
  # leaks into the caller.
  local lBATS_FILE="${1:-}"

  # Regexes that match a bats @test line where the opening brace and
  # possibly an inline body appear on the *same* line, e.g.
  #   @test "my test" { run foo; [ "$status" -eq 0 ]; }
  # The part after '{' is captured in BASH_REMATCH[1] as the inline body.
  local lREGEX_DOUBLE='^[[:space:]]*@test[[:space:]]+"[^"]*"[[:space:]]*\{(.*)$'
  local lREGEX_SINGLE="^[[:space:]]*@test[[:space:]]+'[^']*'[[:space:]]*\\{(.*)$"
  (
    local lBATS_TEMP_FILE=""
    local lBASH_CHECK_RC=0
    local lTEST_CNT=0
    # lTEST_DECL tracks a two-line @test declaration where the body starts
    # on the line *after* the @test line:
    #   @test "my test"        <-- lTEST_DECL becomes 1 here
    #   {                      <-- opening brace found, body follows
    #     run foo
    #   }
    local lTEST_DECL=0
    local lLINE=""
    local lINLINE_TEST_BODY=""

    lBATS_TEMP_FILE="$(mktemp)"
    trap 'rm -f "${lBATS_TEMP_FILE}"' EXIT

    while IFS= read -r lLINE || [[ -n "${lLINE}" ]]; do

      # --- State: we are inside a multi-line @test declaration ---
      # We already wrote the function header on the previous iteration.
      # Now we are looking for the opening '{'.  Everything before it
      # (if any) is the inline body on the same line as '{'.
      if [[ "${lTEST_DECL}" -eq 1 ]]; then
        if [[ "${lLINE}" == *"{"* ]]; then
          # Strip everything up to and including the first '{'
          lINLINE_TEST_BODY="${lLINE#*\{}"
          # Trim leading whitespace from the inline body
          while [[ "${lINLINE_TEST_BODY}" == [[:space:]]* ]]; do
            lINLINE_TEST_BODY="${lINLINE_TEST_BODY#?}"
          done
          # Write the inline body if there is anything left
          if [[ -n "${lINLINE_TEST_BODY}" ]]; then
            printf "%s\n" "${lINLINE_TEST_BODY}" >>"${lBATS_TEMP_FILE}"
          fi
          lTEST_DECL=0
        else
          # No '{' yet — this line is the test body, copy it as-is
          printf "%s\n" "${lLINE}" >>"${lBATS_TEMP_FILE}"
        fi
        continue
      fi

      # --- Match: @test "name" { inline_body }  (single or double quotes) ---
      # The entire @test declaration including an optional inline body fits
      # on one line.  Rewrite it as a plain bash function.
      if [[ "${lLINE}" =~ ${lREGEX_DOUBLE} ]] || [[ "${lLINE}" =~ ${lREGEX_SINGLE} ]]; then
        lINLINE_TEST_BODY="${BASH_REMATCH[1]}"
        ((lTEST_CNT += 1))
        printf "function bats_test_placeholder_%s() {%s\n" "${lTEST_CNT}" "${lINLINE_TEST_BODY}" >>"${lBATS_TEMP_FILE}"
        continue
      fi

      # --- Match: @test "name" (body starts on next line) ---
      # Write only the function header now; the body lines will be copied
      # in subsequent iterations while lTEST_DECL == 1.
      if [[ "${lLINE}" =~ ^[[:space:]]*@test[[:space:]]+ ]]; then
        ((lTEST_CNT += 1))
        printf "function bats_test_placeholder_%s() {\n" "${lTEST_CNT}" >>"${lBATS_TEMP_FILE}"
        lTEST_DECL=1
        continue
      fi

      # --- No bats-specific syntax: pass through unchanged ---
      printf "%s\n" "${lLINE}" >>"${lBATS_TEMP_FILE}"
    done <"${lBATS_FILE}" || exit 1

    # Now that the file is valid bash, let bash -n validate it
    bash -n "${lBATS_TEMP_FILE}" || lBASH_CHECK_RC=$?
    exit "${lBASH_CHECK_RC}"
  )
}

echo -e "\\n${ORANGE}${BOLD}Embedded Linux Analyzer Bash syntax checker${NC}"
echo -e "${BOLD}=================================================================${NC}"

echo -e "\\n${GREEN}Load all sources to check:${NC}\\n"
import_emba_scripts

echo -e "\\n${GREEN}Check all source files for correct bash syntax:${NC}\\n"
for EMBA_SOURCE_FILE in "${EMBA_SOURCES_ARR[@]}"; do
  [[ ! -f "${EMBA_SOURCE_FILE}" ]] && continue
  if [[ "${EMBA_SOURCE_FILE}" == *.bats ]]; then
    echo -e "\\n${GREEN}Run ${ORANGE}bash -n (Bats-mode)${GREEN} on ${ORANGE}${EMBA_SOURCE_FILE}${NC}\\n"
    if check_bats_syntax "${EMBA_SOURCE_FILE}" 2>/dev/null; then
      echo -e "${GREEN}${BOLD}==> SUCCESS${NC}\\n"
    else
      echo -e "\\n${ORANGE}${BOLD}==> FIX ERRORS${NC}\\n"
      check_bats_syntax "${EMBA_SOURCE_FILE}"
      MODULES_TO_CHECK_ARR+=("${EMBA_SOURCE_FILE}")
    fi
    continue
  fi
  echo -e "\\n${GREEN}Run ${ORANGE}bash -n${GREEN} on ${ORANGE}${EMBA_SOURCE_FILE}${NC}\\n"
  if bash -n "${EMBA_SOURCE_FILE}" 2>/dev/null; then
    echo -e "${GREEN}${BOLD}==> SUCCESS${NC}\\n"
  else
    echo -e "\\n${ORANGE}${BOLD}==> FIX ERRORS${NC}\\n"
    bash -n "${EMBA_SOURCE_FILE}"
    MODULES_TO_CHECK_ARR+=("${EMBA_SOURCE_FILE}")
  fi
done

if [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]]; then
  echo -e "${RED}[-] WARNING: Syntax errors detected -> Fix before pushing to EMBA repo${NC}"
  exit 1
fi
exit 0
