#!/bin/bash

EMBA_PATH="."
# shellcheck source=/dev/null
source "${EMBA_PATH}/helpers/helpers_emba_prepare.sh"
# shellcheck source=/dev/null
source "${EMBA_PATH}/helpers/helpers_emba_print.sh"

BLACKLIST_VARS_ARR=("IFS" "EMBA" "MD5_DONE_DEEP" "LOG_PATH_MODULE")

mapfile -t ALL_EMBA_MODULES < <(find "${EMBA_PATH}"/modules -name "*.sh")
mapfile -t ALL_EMBA_HELPERS < <(find "${EMBA_PATH}"/helpers -name "helpers_emba_*.sh")

if [[ "$#" -eq 0 ]] || [[ "${1}" == "all" ]]; then
  SCRIPTS_TO_TEST=("${ALL_EMBA_MODULES[@]}")
  SCRIPTS_TO_TEST+=("${ALL_EMBA_HELPERS[@]}")
  print_output "[*] Testing ${#SCRIPTS_TO_TEST[@]} EMBA scripts" "no_log"
elif [[ "${1}" == "modules" ]]; then
  SCRIPTS_TO_TEST=("${ALL_EMBA_MODULES[@]}")
  print_output "[*] Testing ${#SCRIPTS_TO_TEST[@]} EMBA modules" "no_log"
elif [[ "${1}" == "helpers" ]]; then
  SCRIPTS_TO_TEST=("${ALL_EMBA_HELPERS[@]}")
  print_output "[*] Testing ${#SCRIPTS_TO_TEST[@]} EMBA helpers" "no_log"
elif [[ -f "${1}" ]]; then
  SCRIPTS_TO_TEST=("${1}")
else
  print_output "[*] Usage: ${0} [all, modules, helpers]" "no_log"
  exit 1
fi

UNKNOWN_VARS_CNT_ALL=0
for MODULE in "${SCRIPTS_TO_TEST[@]}"; do
  if [[ "${MODULE}" == *"modules/L10_system_emulation/"* ]]; then
    continue
  fi
  print_output "[*] Testing EMBA script ${MODULE}" "no_log"
  mapfile -t LOCALS_ARR < <(grep -E "local( )+[l]?[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | sed 's/.*local //' | sort -u)
  mapfile -t EXPORTS_ARR < <(grep -E "export( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | sed 's/.*export //' | sort -u)

  mapfile -t UNKNOWN_LOOP_VARS < <(grep -E "for( )+[A-Z]+[a-zA-Z0-9_]+ in .*;" "${MODULE}" | grep -Ev "^#|^$| #" | awk '{print $2}' | sort -u)
  mapfile -t UNKNOWN_ARR_ADD < <(grep -E "^( )+[A-Z]+[a-zA-Z0-9_]+\+=" "${MODULE}" | cut -d '+' -f1 | grep -Ev "^#|^$| #" | tr -d ' ' | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_VAR < <(grep -E "^( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | grep -v "mapfile\|declare\|local\|export\|for\|if" | grep -Ev "^#|^$| #" | tr -d ' ' | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_ARR < <(grep -o -E "mapfile -t( )+[A-Z]+[a-zA-Z0-9_]+" "${MODULE}" | awk '{print $3}' | grep -v "declare\|local\|export\|for\|if" | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_ARR1 < <(grep -o -E "declare -A( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | awk '{print $3}' | cut -d '=' -f1 | grep -v "mapfile\|local\|export\|for\|if" | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_ARR2 < <(grep -o -E "readarray -t( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | awk '{print $3}' | cut -d '=' -f1 | grep -v "mapfile\|declare\|local\|export\|for\|if" | sort -u)

  UNKNOWN_VARS_ARR=( "${UNKNOWN_LOOP_VARS[@]}" "${UNKNOWN_ARR_ADD[@]}" "${UNKNOWN_VARS_ARR_VAR[@]}" "${UNKNOWN_VARS_ARR_ARR[@]}" "${UNKNOWN_VARS_ARR_ARR1[@]}" "${UNKNOWN_VARS_ARR_ARR2[@]}" )
  mapfile -t UNKNOWN_VARS_ARR < <(printf "%s\n" "${UNKNOWN_VARS_ARR[@]}" | sort -u)

  if [[ "${#LOCALS_ARR[@]}" -gt 0 ]]; then
    print_output "$(indent "Found ${#LOCALS_ARR[@]} local variables in ${MODULE}")" "no_log"
    for LOCAL_VAR in "${LOCALS_ARR[@]}"; do
      print_output "$(indent "$(green "[+] local var: ${ORANGE}${LOCAL_VAR}${NC}")")" "no_log"
    done
  fi

  if [[ "${#EXPORTS_ARR[@]}" -gt 0 ]]; then
    print_ln "no_log"
    print_output "$(indent "Found ${#EXPORTS_ARR[@]} global variables in ${MODULE}")" "no_log"
    for EXPORTED_VAR in "${EXPORTS_ARR[@]}"; do
      print_output "$(indent "$(orange "[*] exported var: ${EXPORTED_VAR}")")" "no_log"
    done
  fi

  if [[ "${#UNKNOWN_VARS_ARR[@]}" -gt 0 ]]; then
    print_ln "no_log"
    print_output "$(indent "Found the following indirect global variables in ${MODULE}")" "no_log"
    UNKNOWN_VARS_ARR_CNT=0
    for UNKNOWN_VAR in "${UNKNOWN_VARS_ARR[@]}"; do
      if [[ "${BLACKLIST_VARS_ARR[*]}" == *"${UNKNOWN_VAR}"* ]]; then
        continue
      fi
      if [[ "${EXPORTS_ARR[*]}" != *"${UNKNOWN_VAR}"* ]] && [[ "${LOCALS_ARR[*]}" != *"${UNKNOWN_VAR}"* ]]; then
        print_output "$(indent "$(red "[-] indirect exported var: ${ORANGE}${UNKNOWN_VAR}${NC}")")" "no_log"
        UNKNOWN_VARS_ARR_CNT=$((UNKNOWN_VARS_ARR_CNT+1))
        UNKNOWN_VARS_CNT_ALL=$((UNKNOWN_VARS_CNT_ALL+1))
      fi
    done
    if [[ "${UNKNOWN_VARS_ARR_CNT}" -gt 0 ]]; then
      print_output "$(indent "Found ${UNKNOWN_VARS_ARR_CNT} indirect global variables in ${MODULE}")" "no_log"
    else
      print_output "$(indent "$(green "[+] Found NO indirect global variables in ${MODULE}")")" "no_log"
    fi
  fi
  print_bar "no_log"
done

print_ln "no_log"
if [[ "${UNKNOWN_VARS_CNT_ALL}" -gt 0 ]]; then
  print_output "[-] Found ${ORANGE}${UNKNOWN_VARS_CNT_ALL}${NC} indirect global variables in all modules" "no_log"
  print_output "[*] Fix these issues before pushing to repo" "no_log"
  exit "${UNKNOWN_VARS_CNT_ALL}"
else
  print_output "[+] No indirect global function usage detected ..." "no_log"
  exit 0
fi

