#!/bin/bash
#
EMBA_PATH="."
source "${EMBA_PATH}/helpers/helpers_emba_prepare.sh"
source "${EMBA_PATH}/helpers/helpers_emba_print.sh"

mapfile -t ALL_EMBA_SCRIPTS < <(find "${EMBA_PATH}"/modules -name "*.sh")

for MODULE in "${ALL_EMBA_SCRIPTS[@]}"; do
  if [[ "${MODULE}" == *"modules/L10_system_emulation/"* ]]; then
    continue
  fi
  print_output "[*] Testing EMBA script ${MODULE}" "no_log"
  mapfile -t LOCALS_ARR < <(grep -E "local( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | sed 's/.*local //' | sort -u)
  mapfile -t EXPORTS_ARR < <(grep -E "export( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | sed 's/.*export //' | sort -u)
  mapfile -t UNKNOWN_LOOP_VARS < <(grep -E "for( )+[A-Z]+[a-zA-Z0-9_]+ in .*;" "${MODULE}" | awk '{print $2}' | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_VAR < <(grep -E "^( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | cut -d '=' -f1 | grep -v "mapfile\|declare\|local\|export\|for\|if" | grep -Ev "^#|^$| #|\[" | tr -d ' ' | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_ARR < <(grep -o -E "mapfile -t( )+[A-Z]+[a-zA-Z0-9_]+" "${MODULE}" | awk '{print $3}' | grep -v "declare\|local\|export\|for\|if" | sort -u)
  mapfile -t UNKNOWN_VARS_ARR_ARR1 < <(grep -o -E "declare -A( )+[A-Z]+[a-zA-Z0-9_]+=" "${MODULE}" | awk '{print $3}' | cut -d '=' -f1 | grep -v "mapfile\|local\|export\|for\|if" | sort -u)
  UNKNOWN_VARS_ARR=( "${UNKNOWN_VARS_ARR_VAR[@]}" "${UNKNOWN_VARS_ARR_ARR[@]}" "${UNKNOWN_VARS_ARR_ARR1[@]}" "${UNKNOWN_LOOP_VARS[@]}")
  eval "UNKNOWN_VARS_ARR=($(for i in "${UNKNOWN_VARS_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

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
    print_output "$(indent "Found ${#UNKNOWN_VARS_ARR[@]} indirect global variables in ${MODULE}")" "no_log"
    for UNKNOWN_VAR in "${UNKNOWN_VARS_ARR[@]}"; do
      if [[ "${EXPORTS_ARR[*]}" != *"${UNKNOWN_VAR}"* ]] && [[ "${LOCALS_ARR[*]}" != *"${UNKNOWN_VAR}"* ]]; then
        print_output "$(indent "$(red "[-] indirect exported var: ${ORANGE}${UNKNOWN_VAR}${NC}")")" "no_log"
      fi
    done
  fi
  print_bar "no_log"
done

