#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Searches known locations for package management information
# shellcheck disable=SC2094

S08_submodule_perl_cpan_parser() {
  local lPACKAGING_SYSTEM="perl_cpan_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Perl cpan package management SBOM analysis" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPERL_CPAN_FILES_ARR=()
  local lPACKAGE_FILE=""
  local lPERL_CPAN_PACKAGES_ARR=()
  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lPOS_RES=0

  local lWAIT_PIDS_S08_ARR_LCK=()

  mapfile -t lPERL_CPAN_FILES_ARR < <(grep "cpanfile" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lPERL_CPAN_FILES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPERL_CPAN_FILES_ARR[@]}${NC} perl CPAN package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lPERL_CPAN_FILES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPERL_CPAN_FILES_ARR[@]}${NC} perl CPAN package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lPERL_CPAN_FILES_ARR[@]}" ; do

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if grep -q "requires" "${lPACKAGE_FILE}"; then
        mapfile -t lPERL_CPAN_PACKAGES_ARR < <(grep "requires " "${lPACKAGE_FILE}")
        write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_log "[*] Found perl CPAN package details in ${ORANGE}${lPACKAGE_FILE}${NC}:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

        for lPACKAGE_VERSION in "${lPERL_CPAN_PACKAGES_ARR[@]}" ; do
          perl_cpanfiles_analysis_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPACKAGE_FILE}" "${lPACKAGE_VERSION}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
          max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
          lPOS_RES=1
        done
      fi
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No perl CPAN packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No perl CPAN files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Perl CPAN packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No perl CPAN packages SBOM results available"
  fi
}

perl_cpanfiles_analysis_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGE_FILE="${3:-}"
  local lPACKAGE_VERSION="${4:-}"
  # lPACKAGE_VERSION could look like the following
  # requires 'JSON', '>= 2.00, < 2.80';
  # requires 'Plack', '1.0'; # 1.0 or newer
  # requires 'Mojolicious' => '>=8,<9';
  # requires "Net::SSLeay"     => "1.49";

  local lPACKAGE=""
  local lVERSION=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lCPE_IDENTIFIER="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  lPACKAGE=$(safe_echo "${lPACKAGE_VERSION}" | awk '{print $2}')
  lPACKAGE=${lPACKAGE//\ }
  lPACKAGE=${lPACKAGE//\'}
  lPACKAGE=${lPACKAGE//\"}
  lPACKAGE=${lPACKAGE//,}

  if [[ "${lPACKAGE_VERSION}" =~ .*requires.*\ \=\>\ .* ]]; then
    lVERSION=${lPACKAGE_VERSION/*=>}
    lVERSION=${lVERSION/\;*}
  elif [[ "${lPACKAGE_VERSION}" =~ .*requires.*,.* ]]; then
    lVERSION=${lPACKAGE_VERSION#*,}
    lVERSION=${lVERSION/\;*}
  else
    print_error "[-] Parsing error for cpanfile ${lPACKAGE_FILE} - entry ${lPACKAGE_VERSION}"
    return
  fi
  lVERSION=${lVERSION//\ }
  lVERSION=${lVERSION//\'}
  lVERSION=${lVERSION//\"}
  # we have seen entries with invalid "0" entries in the version -> drop these results here
  if [[ "${lVERSION}" == "0" ]]; then
    return
  fi
  # print_output "[*] cpanfile ${lPACKAGE_FILE} - entry ${lPACKAGE_VERSION} - lPACKAGE ${lPACKAGE} - lVERSION ${lVERSION}"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="unknown"
  fi
  # as we have quite often something like asdf::qwertz as identifier we currently do not generate purl and cpe
  # cpe data looks like: "criteria": "cpe:2.3:a:cpan:parallel\\:\\:forkmanager:*:*:*:*:*:*:*:*",
  # escaping hell looks like: grep "cpe.*cpan:parallel\\\\\\\\:\\\\\\\\:forkmanager" external/nvd-json-data-feeds/CVE-2011/CVE-2011-41xx/CVE-2011-4115.json
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "cpan" "${lPACKAGE}" "${lVERSION}" "${lAPP_ARCH:-NA}")
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:cpan:${lPACKAGE//:/\\\\\\\\:}:${lVERSION//:/\\\\\\\\:}:*:*:*:*:*:*"
  local lSTRIPPED_VERSION=":cpan:${lPACKAGE//:/\\\\\\\\:}:${lVERSION//:/\\\\\\\\:}"

  # add source file path information to our properties array:
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lPACKAGE} / ${lVERSION} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Perl CPAN package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE}" "${lVERSION}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}
