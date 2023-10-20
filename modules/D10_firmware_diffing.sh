#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner
#
# Description:  This module is for the firmware diffing mode. To use the diffing mode
#               a second firmware to compare with the first one needs to be configured
#               via the -o EMBA parameter.
#               This module is doing the main diffing job. This module needs the web reporter
#               enabled, otherwise the results are very confusing.


D10_firmware_diffing() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware diff analysis"
  local NEG_LOG=0  

  if ! command -v ssdeep > /dev/null ; then
    print_output "[-] Missing ssdeep installation"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi
  if ! command -v dot > /dev/null ; then
    print_output "[-] Missing xdot installation"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi
  if ! command -v colordiff > /dev/null ; then
    print_output "[-] Missing colordiff installation"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local FW_FILES1=()
  local FW_FILES2=()
  local HOME_DIR=""
  HOME_DIR="$(pwd)"

  local MD5_FW_BIN1=""
  local MD5_FW_BIN2=""

  # shellcheck disable=SC2153
  MD5_FW_BIN1=$(md5sum "${FIRMWARE_PATH}")
  # shellcheck disable=SC2153
  MD5_FW_BIN2=$(md5sum "${FIRMWARE_PATH1}")
  if [[ "${MD5_FW_BIN1}" == "${MD5_FW_BIN2}" ]]; then
    print_output "[-] Same firmware binary files - no further analysis"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  ! [[ -d "${OUTPUT_DIR_UNBLOB1}" ]] && (echo "No firmware directory 1 found" && return)
  ! [[ -d "${OUTPUT_DIR_UNBLOB2}" ]] && (echo "No firmware directory 2 found" && return)

  # create an overview of the files in both firmware directories
  cd "${OUTPUT_DIR_UNBLOB1}" || return
  mapfile -t FW_FILES1 < <(find . -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
  cd .. || return
  cd "${OUTPUT_DIR_UNBLOB2}" || return
  mapfile -t FW_FILES2 < <(find . -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
  cd "${HOME_DIR}" || return

  # lets iterate through the files from firmware 1 and check if they are available in firmware 2
  # if they are also available we are going to check the diffs with ssdeep
  for FW_FILE1 in "${FW_FILES1[@]}"; do
    FW_FILE1="${OUTPUT_DIR_UNBLOB1}""${FW_FILE1#.}"

    FW_FILE_NAME1=$(basename "${FW_FILE1}")
    # print_output "[*] Testing $FW_FILE1"

    # find the file in OUTPUT_DIR_UNBLOB2
    mapfile -t FW_FILES1in2 < <(find "${OUTPUT_DIR_UNBLOB2}" -type f -name "${FW_FILE_NAME1}" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

    if [[ "${#FW_FILES1in2[@]}" -ne 0 ]]; then
      for FW_FILE2 in "${FW_FILES1in2[@]}"; do

        MD5_FW_FILE1=$(md5sum "${FW_FILE1}" | awk '{print $1}')
        MD5_FW_FILE2=$(md5sum "${FW_FILE2}" | awk '{print $1}')
        if [[ "${MD5_FW_FILE1}" != "${MD5_FW_FILE2}" ]]; then
          SSDEEP_OUT=$(ssdeep -d -s "${FW_FILE1}" "${FW_FILE2}")
          [[ -z "${SSDEEP_OUT}" ]] && continue
          # extract the ssdeep ranking from the output
          SSDEEP_RANK=$(echo "${SSDEEP_OUT}" | rev | awk '{print $1}' | rev | tr -d '(' | tr -d ')')
          NEG_LOG=1

          LOG_FILE_SUB_NAME="diff_report_${FW_FILE_NAME1}.txt"
          LOG_PATH_MODULE_SUB="${LOG_PATH_MODULE}"/"${LOG_FILE_SUB_NAME/.txt}"
          LOG_FILE_DETAILS="${LOG_PATH_MODULE_SUB}/${LOG_FILE_SUB_NAME}"

          ! [[ -d "${LOG_PATH_MODULE_SUB}" ]] && mkdir "${LOG_PATH_MODULE_SUB}"

          # we only look at files ranking lt 90 in ssdeep - probably we need to adjust this in the future
          if [[ "${SSDEEP_RANK}" -lt 90 ]]; then
            print_ln "no_log"
            if [[ "$(file "${FW_FILE1}")" == *"text"* ]]; then
              print_output "[+] Found modified ASCII file ${ORANGE}${FW_FILE_NAME1}${GREEN} in 2nd firmware directory - Ranking ${ORANGE}${SSDEEP_RANK}${NC}" "" "${LOG_FILE_DETAILS}"
              write_log "[+] Found modified ASCII file ${ORANGE}${FW_FILE_NAME1}${GREEN} in 2nd firmware directory - Ranking ${ORANGE}${SSDEEP_RANK}${NC}" "${LOG_FILE_DETAILS}"
            else
              print_output "[+] Found modified binary file ${ORANGE}${FW_FILE_NAME1}${GREEN} in 2nd firmware directory - Ranking ${ORANGE}${SSDEEP_RANK}${NC}" "" "${LOG_FILE_DETAILS}"
              write_log "[+] Found modified binary file ${ORANGE}${FW_FILE_NAME1}${GREEN} in 2nd firmware directory - Ranking ${ORANGE}${SSDEEP_RANK}${NC}" "${LOG_FILE_DETAILS}"
            fi
            write_log "" "${LOG_FILE_DETAILS}"
            write_log "[*] Base firmware file details to compare with:" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(print_path "${FW_FILE1}")")")" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(md5sum "${FW_FILE1}")")")" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(file "${FW_FILE1}")")")" "${LOG_FILE_DETAILS}"
            write_log "" "${LOG_FILE_DETAILS}"
            write_log "[*] Second firmware file details:" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(print_path "${FW_FILE2}")")")" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(md5sum "${FW_FILE2}")")")" "${LOG_FILE_DETAILS}"
            write_log "$(indent "$(orange "$(file "${FW_FILE2}")")")" "${LOG_FILE_DETAILS}"

            if [[ "$(file "${FW_FILE1}")" == *"text"* ]]; then
              sub_module_title "Diff for clear text file ${FW_FILE_NAME1}" "${LOG_FILE_DETAILS}"
              # clear text handling - just colordiffing
              diff -yb --color=always --suppress-common-lines "${FW_FILE1}" "${FW_FILE2}" > "${LOG_PATH_MODULE_SUB}"/colordiff_"${FW_FILE_NAME1}".txt || true
              if [[ -f "${LOG_PATH_MODULE_SUB}"/colordiff_"${FW_FILE_NAME1}".txt ]]; then
                print_output "[*] Diffing results from clear text file ${ORANGE}${FW_FILE_NAME1}${NC} logged to ${ORANGE}${LOG_PATH_MODULE_SUB}/colordiff_${FW_FILE_NAME1}.txt${NC}" "no_log"
                write_log "" "${LOG_FILE_DETAILS}"
                write_log "[*] Diffing results from clear text file ${ORANGE}${FW_FILE_NAME1}${NC}" "${LOG_FILE_DETAILS}"
                write_log "" "${LOG_FILE_DETAILS}"
                cat "${LOG_PATH_MODULE_SUB}"/colordiff_"$(basename "${FW_FILE1}")".txt >> "${LOG_FILE_DETAILS}"
              fi
            else
              sub_module_title "Diff for binary file ${FW_FILE_NAME1}" "${LOG_FILE_DETAILS}"
              # binary handling - colordiffing the hex dump and some radare2 diffing
              diff -yb --color=always --suppress-common-lines <(xxd "${FW_FILE1}") <(xxd "${FW_FILE2}") > "${LOG_PATH_MODULE_SUB}"/colordiff_"${FW_FILE_NAME1}".txt || true
              if [[ -f "${LOG_PATH_MODULE_SUB}"/colordiff_"${FW_FILE_NAME1}".txt ]]; then
                print_output "[*] Diffing results from binary file ${ORANGE}${FW_FILE_NAME1}${NC} logged to ${ORANGE}${LOG_PATH_MODULE_SUB}/colordiff_${FW_FILE_NAME1}.txt${NC}" "no_log"
                write_log "" "${LOG_FILE_DETAILS}"
                # we only link to the binary colordiff in the web report:
                # on the cli output we do not see the complete diff
                write_log "[*] Diffing results from binary file ${ORANGE}${FW_FILE_NAME1}${NC}" "${LOG_FILE_DETAILS}"
                write_link "${LOG_PATH_MODULE_SUB}/colordiff_${FW_FILE_NAME1}.txt" "${LOG_FILE_DETAILS}"
                write_log "" "${LOG_FILE_DETAILS}"
              fi
              write_log "" "${LOG_FILE_DETAILS}"

              # radare2:
              sub_module_title "Non matching functions for binary file ${FW_FILE_NAME1}" "${LOG_FILE_DETAILS}"
              write_log "" "${LOG_FILE_DETAILS}"
              write_log "[*] Non matching functions in ${ORANGE}$(basename "${FW_FILE1}")${NC}:" "${LOG_FILE_DETAILS}"
              print_output "[*] Non matching functions in ${ORANGE}$(basename "${FW_FILE1}")${NC} logged to ${ORANGE}${LOG_PATH_MODULE_SUB}/r2_diff_fct_${FW_FILE_NAME1}_${FW_FILE_NAME1}.txt${NC}" "no_log"
              # get the functions which are different with radiff2:
              radiff2 -AC "${FW_FILE1}" "${FW_FILE2}" 2>/dev/null | grep UNMATCH > "${LOG_PATH_MODULE_SUB}"/r2_diff_fct_"${FW_FILE_NAME1}"_"${FW_FILE_NAME1}".txt
              cat "${LOG_PATH_MODULE_SUB}"/r2_diff_fct_"${FW_FILE_NAME1}"_"${FW_FILE_NAME1}".txt >> "${LOG_FILE_DETAILS}"
              mapfile -t UNMATCHED_FCTs < <(awk '{print $1}' "${LOG_PATH_MODULE_SUB}"/r2_diff_fct_"${FW_FILE_NAME1}"_"${FW_FILE_NAME1}".txt | sort -u)
              write_log "" "${LOG_FILE_DETAILS}"

              sub_module_title "R2 diff for binary file ${FW_FILE_NAME1}" "${LOG_FILE_DETAILS}"

              # let's do a diff on the complete radare2 output:
              # shellcheck disable=SC2016
              r2 -e io.cache=true -e scr.color=false -A -q -c 'pd $s' "${FW_FILE1}" 2>/dev/null > "${LOG_PATH_MODULE_SUB}"/r2_disasm_"${FW_FILE_NAME1}"_dir1.txt
              # shellcheck disable=SC2016
              r2 -e io.cache=true -e scr.color=false -A -q -c 'pd $s' "${FW_FILE2}" 2>/dev/null > "${LOG_PATH_MODULE_SUB}"/r2_disasm_"$(basename "${FW_FILE2}")"_dir2.txt
              diff -yb --color=always --suppress-common-lines "${LOG_PATH_MODULE_SUB}"/r2_disasm_"$(basename "${FW_FILE1}")"_dir1.txt "${LOG_PATH_MODULE_SUB}"/r2_disasm_"$(basename "${FW_FILE2}")"_dir2.txt 2>/dev/null > "${LOG_PATH_MODULE_SUB}"/colordiff_radare2_disasm_"$(basename "${FW_FILE1}")".txt || true
              if [[ -f "${LOG_PATH_MODULE_SUB}"/colordiff_radare2_disasm_"${FW_FILE_NAME1}".txt ]]; then
                print_output "[*] Radare2 binary diffing results from binary file ${ORANGE}${FW_FILE_NAME1}${NC} logged to ${ORANGE}${LOG_FILE_DETAILS}${NC}." "no_log"
                write_log "[*] Radare2 binary diffing results from binary file ${ORANGE}${FW_FILE_NAME1}${NC}" "${LOG_FILE_DETAILS}"
                write_link "${LOG_PATH_MODULE_SUB}"/colordiff_radare2_disasm_"${FW_FILE_NAME1}".txt "${LOG_FILE_DETAILS}"
                write_log "" "${LOG_FILE_DETAILS}"
              fi

              # now we check diff all the functions with differences and generate a xdot and png picture
              # see also https://book.rada.re/tools/radiff2/binary_diffing.html
              ! [[ -d "${LOG_PATH_MODULE}"/r2_fct_graphing/ ]] && mkdir "${LOG_PATH_MODULE}"/r2_fct_graphing/
              write_log "[*] Radare2 binary function diff for ${ORANGE}${FW_FILE_NAME1}${NC}:" "${LOG_FILE_DETAILS}"

              for FCT in "${UNMATCHED_FCTs[@]}"; do
                write_log "" "${LOG_FILE_DETAILS}"
                radiff2 -e bin.cache=true -md -g "${FCT}" "${FW_FILE2}" "${FW_FILE1}" 2>/dev/null > "${LOG_PATH_MODULE}"/r2_fct_graphing/r2_fct_graph_"${FW_FILE_NAME1}"_"${FCT}".xdot
                if [[ -s "${LOG_PATH_MODULE}"/r2_fct_graphing/r2_fct_graph_"${FW_FILE_NAME1}"_"${FCT}".xdot ]]; then
                  dot -Tpng "${LOG_PATH_MODULE}"/r2_fct_graphing/r2_fct_graph_"${FW_FILE_NAME1}"_"${FCT}".xdot 2>/dev/null > "${LOG_PATH_MODULE}"/r2_fct_graphing/r2_fct_graph_"${FW_FILE_NAME1}"_"${FCT}".png || true
                fi
                if [[ -s "${LOG_PATH_MODULE}/r2_fct_graphing/r2_fct_graph_${FW_FILE_NAME1}_${FCT}.png" ]]; then
                  write_log "[*] Radare2 binary function diff for function ${ORANGE}${FCT}${NC} in binary ${ORANGE}${FW_FILE_NAME1}${NC}" "${LOG_FILE_DETAILS}"
                  write_link "${LOG_PATH_MODULE}/r2_fct_graphing/r2_fct_graph_${FW_FILE_NAME1}_${FCT}.png" "${LOG_FILE_DETAILS}"
                else
                  write_log "[-] No function graph available for ${ORANGE}${FCT}${NC}" "${LOG_FILE_DETAILS}"
                fi
              done
            fi
            write_log "" "${LOG_FILE_DETAILS}"
          fi
        fi
      done
    else
      # deleted files in 2nd firmware directory
      if [[ -f "${FW_FILE1}" ]]; then
        if file "${FW_FILE1}" | grep -q ASCII; then
          cp "${FW_FILE1}" "${LOG_PATH_MODULE}"/"${FW_FILE_NAME1}".log
          print_output "[+] Firmware ASCII file ${ORANGE}${FW_FILE_NAME1}${GREEN} is deleted in ${ORANGE}${OUTPUT_DIR_UNBLOB2}${GREEN}."
        else
          print_output "[+] Firmware binary file ${ORANGE}${FW_FILE_NAME1}${GREEN} is deleted in ${ORANGE}${OUTPUT_DIR_UNBLOB2}${GREEN}."
        fi
        [[ -f "${LOG_PATH_MODULE}"/"${FW_FILE_NAME1}".log ]] && write_link "${LOG_PATH_MODULE}/${FW_FILE_NAME1}.log"
      fi
    fi
  done

  check_for_new_files

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

check_for_new_files() {
  # check for files that are not in the first directory -> new files in the second firmware
  for FW_FILE2 in "${FW_FILES2[@]}"; do
    FW_FILE2="${OUTPUT_DIR_UNBLOB2}""${FW_FILE2#.}"
    # print_output "[*] Testing $FW_FILE2" "no_log"

    FW_FILE_NAME2=$(basename "${FW_FILE2}")

    # find the file in OUTPUT_DIR_UNBLOB1 - the first firmware directory
    mapfile -t FW_FILES1 < <(find "${OUTPUT_DIR_UNBLOB1}" -type f -name "${FW_FILE_NAME2}" | head -1)

    # if we do not find a file in our first directory this file is a new file in the 2nd firmware
    if [[ "${#FW_FILES1[@]}" -eq 0 ]]; then
      if [[ -f "${FW_FILE2}" ]]; then
        if file "${FW_FILE2}" | grep -q ASCII; then
          cp "${FW_FILE2}" "${LOG_PATH_MODULE}"/"${FW_FILE_NAME2}".log
          print_output "[+] Firmware ASCII file ${ORANGE}${FW_FILE_NAME2}${GREEN} is a new file in ${ORANGE}${OUTPUT_DIR_UNBLOB2}${GREEN}."
          [[ -f "${LOG_PATH_MODULE}"/"${FW_FILE_NAME2}".log ]] && write_link "${LOG_PATH_MODULE}/${FW_FILE_NAME2}.log"
        else
          print_output "[+] Firmware binary file ${ORANGE}${FW_FILE_NAME2}${GREEN} is a new file in ${ORANGE}${OUTPUT_DIR_UNBLOB2}${GREEN}."
        fi
      fi

    fi
  done


}
