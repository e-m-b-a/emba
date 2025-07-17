#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Scrapes firmware for certification files and their end date.

S60_cert_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search certificates"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCERT_FILES_ARR=()
  readarray -t lCERT_FILES_ARR < <(config_find "${CONFIG_DIR}""/cert_files.cfg")

  local lCERT_FILES_CNT=0
  local lTOTAL_CERT_CNT=0
  local lCERT_OUT_CNT=0
  local lCURRENT_DATE=""
  local lCERT_ENTRY=""
  local lCERT_DATE=""
  local lCERT_DATE_=""
  local lCERT_NAME=""
  local lCERT_LOG=""
  local lNESTED_CERT_CNT=0
  local lFUTURE_DATE=""
  local lEXPIRE_WATCH_DATE="2 years"
  local lSPECIFIC_CERT=""
  local lCERT_WARNING_CNT=0
  local lSIGNATURE=""

  if [[ "${lCERT_FILES_ARR[0]-}" == "C_N_F" ]]; then print_output "[!] Config not found"
  elif [[ ${#lCERT_FILES_ARR[@]} -ne 0 ]]; then
    write_csv_log "Certificate file" "Certificate expire on" "Certificate expired"
    print_output "[+] Found ""${ORANGE}${#lCERT_FILES_ARR[@]}${GREEN}"" possible certification files:"
    print_ln
    lCURRENT_DATE=$(date +%s)
    lFUTURE_DATE=$(date --date="${lEXPIRE_WATCH_DATE}" +%s)
    for lCERT_ENTRY in "${lCERT_FILES_ARR[@]}" ; do
      if [[ -f "${lCERT_ENTRY}" && $(wc -l < "${lCERT_ENTRY}") -gt 1 ]]; then
        ((lCERT_FILES_CNT+=1))
        if command -v openssl > /dev/null ; then
          lCERT_NAME=$(basename "${lCERT_ENTRY}")
          lCERT_LOG="${LOG_PATH_MODULE}/cert_details_${lCERT_NAME}.txt"
          write_log "[*] Cert file: ${lCERT_ENTRY}\n" "${lCERT_LOG}"
          timeout --preserve-status --signal SIGINT 10 openssl storeutl -noout -text -certs "${lCERT_ENTRY}" 2>/dev/null >> "${lCERT_LOG}" || true
          lNESTED_CERT_CNT=$(tail -n 1 < "${lCERT_LOG}" | grep -o '[0-9]\+' || true)
          if ! [[ "${lNESTED_CERT_CNT}" =~ ^[0-9]+$ ]]; then
            print_output "[-] Something went wrong for certificate ${lCERT_ENTRY}" "no_log"
            continue
          fi
          lTOTAL_CERT_CNT=$((lTOTAL_CERT_CNT + lNESTED_CERT_CNT))
          for ((i=1; i<=lNESTED_CERT_CNT; i++)); do
            index=$((i - 1))
            lCERT_DATE=$(date --date="$(grep 'Not After :' "${lCERT_LOG}" | awk -v cnt="${i}" 'NR==cnt {sub(/.*: /, ""); print}')" --iso-8601 || true)
            lCERT_DATE_=$(date --date="$(grep 'Not After :' "${lCERT_LOG}" | awk -v cnt="${i}" 'NR==cnt {sub(/.*: /, ""); print}')" +%s || true)
            lSIGNATURE=$(sed -n '/Signature Value:/!b;n;p' "${lCERT_LOG}" | sed -n "${i}p" | xargs)
            lSPECIFIC_CERT=$(head -n -1 < "${lCERT_LOG}" | awk -v idx="${index}" '
            BEGIN { found = 0 }
            /^[0-9]+: Certificate$/ {
                if (found) {
                  print cert;
                  cert = "";
                  found = 0
                }
            }
            $1 == idx ":" && !found {
                found = 1
            }
            found {
                cert = cert $0 ORS
            }
            END {
                if (found) {
                    print cert
                }
            }' | tail -n+2)

            if [[ ${lCERT_DATE_} -lt ${lCURRENT_DATE} ]]; then
              print_output "  ${RED}${lCERT_DATE} - $(print_path "${lCERT_ENTRY}") ${lSIGNATURE} ${NC}" "" "${lSPECIFIC_CERT}"
              write_csv_log "${lCERT_ENTRY}" "${lCERT_DATE_}" "yes"
              ((lCERT_OUT_CNT+=1))
            elif [[ ${lCERT_DATE_} -le ${lFUTURE_DATE} ]]; then
              print_output "  ${ORANGE}${lCERT_DATE} - $(print_path "${lCERT_ENTRY}") ${lSIGNATURE} ${NC}" "" "${lSPECIFIC_CERT}"
              write_csv_log "${lCERT_ENTRY}" "${lCERT_DATE_}" "expires within ${lEXPIRE_WATCH_DATE}"
              ((lCERT_WARNING_CNT+=1))
            else
              print_output "  ${GREEN}${lCERT_DATE} - $(print_path "${lCERT_ENTRY}") ${lSIGNATURE} ${NC}" "" "${lSPECIFIC_CERT}"
              write_csv_log "${lCERT_ENTRY}" "${lCERT_DATE_}" "no"
            fi
          done
        else
          print_output "$(indent "$(orange "$(print_path "${lCERT_ENTRY}")")")"
          write_csv_log "${lCERT_ENTRY}" "unknown" "unknown"
        fi
      fi
    done
    write_log ""
    write_log "[*] Statistics:${lTOTAL_CERT_CNT}:${lCERT_FILES_CNT}:${lCERT_OUT_CNT}:${lCERT_WARNING_CNT}"
  else
    print_output "[-] No certification files found"
  fi

  module_end_log "${FUNCNAME[0]}" "${lTOTAL_CERT_CNT}"
}

