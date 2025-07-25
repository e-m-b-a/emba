#!/bin/bash -p
# shellcheck disable=SC2001

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
# Author(s): Pascal Eckmann,
# Contributors: Michael Messner, Stefan Haboeck

export INDEX_FILE="index.html"
export MAIN_LOG="./emba.log"
export STYLE_PATH="/style"
export TEMP_PATH="/tmp"
export ERR_PATH="/err"
export SUPPL_PATH_HTML="/etc"

# variables for html style
export P_START="<pre>"
export P_END="</pre>"
export SPAN_RED="<span class=\"red\">"
export SPAN_GREEN="<span class=\"green\">"
export SPAN_ORANGE="<span class=\"orange\">"
export SPAN_BLUE="<span class=\"blue\">"
export SPAN_MAGENTA="<span class=\"magenta\">"
export SPAN_CYAN="<span class=\"cyan\">"
export SPAN_BOLD="<span class=\"bold\">"
export SPAN_ITALIC="<span class=\"italic\">"
export SPAN_END="</span>"
export HR_MONO="<hr class=\"mono\" />"
export HR_DOUBLE="<hr class=\"double\" />"
export BR="<br />"
export LINK="<a href=\"LINK\" title=\"LINK\" target=\"_blank\" >"
export ARROW_LINK="<a href=\"LINK\" title=\"LINK\" >"
export LOCAL_LINK="<a class=\"local\" href=\"LINK\" title=\"LINK\" >"
export REFERENCE_LINK="<a class=\"reference\" href=\"LINK\" title=\"LINK\" >"
export REFERENCE_MODUL_LINK="<a class=\"refmodul\" href=\"LINK\" title=\"LINK\" >"
export LOCAL_OVERLAY_LINK="<a class=\"refmodul\" onclick=\"overlay_output\(\"LINK\"\) >"
export REFERENCE_MODUL_EXT_LINK="<a class=\"refmodulext\" href=\"LINK\" title=\"LINK\" target=\"_blank\">"
export EXPLOIT_LINK="<a href=\"https://www.exploit-db.com/exploits/LINK\" title=\"LINK\" target=\"_blank\" >"
export CVE_LINK="<a href=\"https://nvd.nist.gov/vuln/detail/LINK\" title=\"LINK\" target=\"_blank\" >"
export CWE_LINK="<a href=\"https://cwe.mitre.org/data/definitions/LINK.html\" title=\"LINK\" target=\"_blank\" >"
export GITHUB_LINK="<a href=\"https://github.com/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
export SNYK_LINK="<a href=\"https://security.snyk.io/vuln/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
export PSS_LINK="<a href=\"https://packetstormsecurity.com/files/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
export LICENSE_LINK="<a href=\"LINK\" title=\"LINK\" target=\"_blank\" >"
export MODUL_LINK="<a class=\"modul\" href=\"LINK\" title=\"LINK\" >"
export MODUL_INDEX_LINK="<a class=\"modul CLASS\" data=\"DATA\" href=\"LINK\" title=\"LINK\">"
export ETC_INDEX_LINK="<a class=\"etc\" href=\"LINK\" title=\"LINK\">"
export SUBMODUL_LINK="<a class=\"submodul\" href=\"LINK\" title=\"LINK\" >"
export ANCHOR="<a class=\"anc\" id=\"ANCHOR\">"
export TITLE_ANCHOR="<a id=\"ANCHOR\">"
export LINK_END="</a>"
export DEPTH="."

add_color_tags() {
  local lCOLOR_FILE="${1:-}"
  sed -i -E \
    -e 's@\x1b\[@;@g ; s@;[0-9]{0};@;00;@g ; s@;([0-9]{1});@;0\1;@g ; s@;([0-9]{2});@;\1;@g ' \
    -e 's@;([0-9]{0})(m){1}@;00@g ; s@;([0-9]{1})(m){1}@;0\1@g ; s@;([0-9]{2})(m){1}@;\1@g ' \
    -e "s@;31@${SPAN_RED}@g ; s@;32@${SPAN_GREEN}@g ; s@;33@${SPAN_ORANGE}@g" \
    -e "s@;34@${SPAN_BLUE}@g ; s@;35@${SPAN_MAGENTA}@g ; s@;36@${SPAN_CYAN}@g" \
    -e "s@;01@${SPAN_BOLD}@g ; s@;03@${SPAN_ITALIC}@g ; s@;00@${SPAN_END}@g" \
    -e "s@;[0-9]{2}@@g ; s@${P_START}${P_END}@${BR}@g" "${lCOLOR_FILE}" || true
}

add_link_tags() {
  local lLINK_FILE="${1:-}"
  local lBACK_LINK="${2:-}"
  # If a module generates for example a list with links to referenced files ([REF]-tag), you don't want additional links in this list
  # set the third parameter to '1' to only generate [REF] links
  local lIGNORE_LINKS="${3:-0}"

  local lLINK_COMMAND_ARR=()
  local lWAIT_PIDS_WR=()
  local lREF_LINK_NUMBER=""

  # [REF] anchor
  if ( grep -a -q -E '\[REF\]' "${lLINK_FILE}" ) ; then
    readarray -t REF_LINKS_L_NUMBER < <(grep -a -n -E '\[REF\].*' "${lLINK_FILE}" | cut -d':' -f1 )
    # print_output "[*] REF link found in ${lLINK_FILE}" "no_log"
    for lREF_LINK_NUMBER in "${REF_LINKS_L_NUMBER[@]}" ; do
      DEPTH="."
      local lREF_LINK=""
      local lHTML_LINK=""
      local lLINE_NUMBER_INFO_PREV=""
      lREF_LINK="$(sed "${lREF_LINK_NUMBER}""q;d" "${lLINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
      local lURL_REGEX='(www.|https?|ftp|file):\/\/'
      if [[ -f "$(echo "${lREF_LINK}" | cut -d"#" -f1)" ]] ; then
        if [[  ( ("${lREF_LINK: -4}" == ".txt") || ("${lREF_LINK: -4}" == ".log") || ("${lREF_LINK: -4}" == ".csv")) || ( ("${lREF_LINK}" == *".txt#"*) || ("${lREF_LINK}" == *".log#"*) || ("${lREF_LINK: -2}" == ".c") ) ]] ; then
          local lREF_ANCHOR=""
          if [[ ( ("${lREF_LINK}" == *".txt#"*) || ("${lREF_LINK}" == *".log#"*) ) ]] ; then
            lREF_ANCHOR="$(echo "${lREF_LINK}" | cut -d"#" -f2 || true)"
            lREF_LINK="$(echo "${lREF_LINK}" | cut -d"#" -f1 || true)"
          fi
          # print_output "[*] REF link ${lREF_LINK} found in ${lLINK_FILE}" "no_log"
          # generate reference file
          generate_info_file "${lREF_LINK}" "${lBACK_LINK}" &
          lWAIT_PIDS_WR+=( "$!" )

          if [[ -n "${lREF_ANCHOR}" ]] ; then
            lHTML_LINK="$(echo "${REFERENCE_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${lBACK_LINK}" | cut -d"." -f1)/$(basename "${lREF_LINK%."${lREF_LINK##*.}"}").html""#anchor_${lREF_ANCHOR}@g" || true)"
          else
            lHTML_LINK="$(echo "${REFERENCE_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${lBACK_LINK}" | cut -d"." -f1)/$(basename "${lREF_LINK%."${lREF_LINK##*.}"}").html@g" || true)"
          fi
          lLINE_NUMBER_INFO_PREV="$(( lREF_LINK_NUMBER - 1 ))"
          while [[ ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${BR}" ) ]] ; do
            lLINE_NUMBER_INFO_PREV=$(( lLINE_NUMBER_INFO_PREV - 1 ))
          done
          lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@^@'"${lHTML_LINK}"'@' "${lLINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
        elif [[ "${lREF_LINK: -5}" == ".json" || "${lREF_LINK: -6}" == ".proto" || "${lREF_LINK: -4}" == ".xml" || "${lREF_LINK: -5}" == ".spdx" ]]; then
          lLINE_NUMBER_INFO_PREV="$(grep -a -n -m 1 -E "\[REF\] ""${lREF_LINK}" "${lLINK_FILE}" | cut -d":" -f1 || true)"
          local lRES_PATH=""
          lRES_PATH="${ABS_HTML_PATH}""/""$(echo "${lBACK_LINK}" | cut -d"." -f1 )""/res"
          if [[ ! -d "${lRES_PATH}" ]] ; then mkdir -p "${lRES_PATH}" > /dev/null || true ; fi
          cp "${lREF_LINK}" "${lRES_PATH}""/""$(basename "${lREF_LINK}")" || true

          lLINE_NUMBER_INFO_PREV="$(( lREF_LINK_NUMBER - 1 ))"
          lHTML_LINK="$(echo "${REFERENCE_LINK}" | sed -e "s@LINK@./$(echo "${lBACK_LINK}" | cut -d"." -f1 )/res/$(basename "${lREF_LINK}")@g" || true)"

          lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@^@'"${lHTML_LINK}"'@' "${lLINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
        elif [[ "${lREF_LINK: -7}" == ".tar.gz" ]] ; then
          local lRES_PATH=""
          lRES_PATH="${ABS_HTML_PATH}""/""$(echo "${lBACK_LINK}" | cut -d"." -f1 )""/res"
          if [[ ! -d "${lRES_PATH}" ]] ; then mkdir -p "${lRES_PATH}" > /dev/null || true ; fi
          cp "${lREF_LINK}" "${lRES_PATH}""/""$(basename "${lREF_LINK}")" || true
          lHTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${lBACK_LINK}" | cut -d"." -f1 )/res/$(basename "${lREF_LINK}")@g" || true)""Download Qemu emulation archive.""${LINK_END}"
          sed -i "s@Qemu emulation archive created in log directory.*$(basename "${lREF_LINK}").*@${lHTML_LINK}${P_END}@" "${lLINK_FILE}"
        elif [[ "${lREF_LINK: -4}" == ".png" ]] ; then
          lLINE_NUMBER_INFO_PREV="$(grep -a -n -m 1 -E "\[REF\] ""${lREF_LINK}" "${lLINK_FILE}" | cut -d":" -f1 || true)"
          cp "${lREF_LINK}" "${ABS_HTML_PATH}${STYLE_PATH}""/""$(basename "${lREF_LINK}")" || true

          if [[ "$(echo "${lREF_LINK}" | rev | cut -d '/' -f4- | rev)" == "${LOG_DIR}" ]]; then
            DEPTH=".."
          elif [[ "$(echo "${lREF_LINK}" | rev | cut -d '/' -f3- | rev)" == "${LOG_DIR}" ]]; then
            DEPTH="."
          fi
          local lIMAGE_LINK="<img class=\"image\" src=\"${DEPTH}${STYLE_PATH}/PICTURE\">"
          lHTML_LINK="$(echo "${lIMAGE_LINK}" | sed -e 's@PICTURE@'"$(basename "${lREF_LINK}")"'@' || true)"
          lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@$@'"${lHTML_LINK}"'@' )
        fi
      elif [[ ("${lREF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}$ ) || ("${lREF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}\#.*$ ) ]] ; then
        local lREF_ANCHOR=""
        if [[ "${lREF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}\#.*$ ]] ; then
          lREF_ANCHOR="$(echo "${lREF_LINK}" | cut -d"#" -f2 || true)"
          lREF_LINK="$(echo "${lREF_LINK}" | cut -d"#" -f1 || true)"
        fi
        # link modules
        local lMODUL_ARR_LINK=()
        readarray -t lMODUL_ARR_LINK < <( find ./modules \( -iname "${lREF_LINK}""_*.sh" ! -iname "*pre.sh" ! -iname "*post.sh" \) || true )
        if [[ "${#lMODUL_ARR_LINK[@]}" -gt 0 ]] ; then
          local lMODUL_ARR_LINK_E=""
          lMODUL_ARR_LINK_E="$(echo "${lMODUL_ARR_LINK[0]}" | tr '[:upper:]' '[:lower:]' || true)"
          if [[ -n "${lREF_ANCHOR}" ]] ; then
            lHTML_LINK="$(echo "${REFERENCE_MODUL_LINK}" | sed -e "s@LINK@./$(basename "${lMODUL_ARR_LINK_E%.sh}").html\#anchor_${lREF_ANCHOR}@" || true)"
          else
            lHTML_LINK="$(echo "${REFERENCE_MODUL_LINK}" | sed -e "s@LINK@./$(basename "${lMODUL_ARR_LINK_E%.sh}").html@" || true)"
          fi
          lLINE_NUMBER_INFO_PREV="$(( lREF_LINK_NUMBER - 1 ))"
          while [[ "$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${P_START}${SPAN_END}${P_END}" ]] ; do
            lLINE_NUMBER_INFO_PREV=$(( lLINE_NUMBER_INFO_PREV - 1 ))
          done
          lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@^@'"${lHTML_LINK}"'@' "${lLINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
        fi
      elif [[ "${lREF_LINK}" =~ ${lURL_REGEX} ]] ; then
        lLINE_NUMBER_INFO_PREV="$(( lREF_LINK_NUMBER - 1 ))"
        while [[ ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${BR}" ) ]] ; do
          lLINE_NUMBER_INFO_PREV=$(( lLINE_NUMBER_INFO_PREV - 1 ))
        done
        lHTML_LINK="$(echo "${REFERENCE_MODUL_EXT_LINK}" | sed -e "s@LINK@${lREF_LINK}@")""$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")""${LINK_END}"
        lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@.*@'"${lHTML_LINK}"'@' )
      else
        lLINE_NUMBER_INFO_PREV="$(grep -a -n -E "\[REF\] ""${lREF_LINK}" "${lLINK_FILE}" | cut -d":" -f1 || true)"
      fi
    done
  fi

  if [[ ${lIGNORE_LINKS} -eq 0 ]] ; then
    # web links
    if ( grep -a -q -E '(https?|ftp|file):\/\/' "${lLINK_FILE}" ) ; then
      local lWEB_LINKS=()
      local lWEB_LINK=""
      local lWEB_LINK_LINE_NUM=""
      local lWEB_LINK_URL=""
      readarray -t lWEB_LINKS < <( grep -a -n -o -E '(\b(https?|ftp|file):\/\/) ?[-A-Za-z0-9+&@#\/%?=~_|!:,.;]+[-A-Za-z0-9+&@#\/%=~a_|]' "${lLINK_FILE}" | uniq || true)
      for lWEB_LINK in "${lWEB_LINKS[@]}" ; do
        lWEB_LINK_LINE_NUM="$(echo "${lWEB_LINK}" | cut -d ":" -f 1 || true)"
        lWEB_LINK_URL="$(echo "${lWEB_LINK}" | cut -d ":" -f 2- || true)"
        lWEB_LINK_URL="${lWEB_LINK_URL%\\}"
        if [[ -n "${lWEB_LINK}" ]] ; then
          lHTML_LINK="$(echo "${LINK}" | sed -e "s@LINK@${lWEB_LINK_URL}@g")""${lWEB_LINK_URL}""${LINK_END}" || true
          lLINK_COMMAND_ARR+=( "${lWEB_LINK_LINE_NUM}"'s@'"${lWEB_LINK_URL}"'@'"${lHTML_LINK}"'@' )
        fi
      done
    fi

    # linux exploit suggester links
    if ( grep -a -q -E 'Exploit \(linux-exploit-suggester' "${lLINK_FILE}" ) ; then
      local lLES_LINE_ARR=()
      local lLES_LINE=""
      readarray -t lLES_LINE_ARR < <( grep -a -o -n -E 'Exploit \(linux-exploit-suggester' "${lLINK_FILE}" | cut -d":" -f1)
      for lLES_LINE in "${lLES_LINE_ARR[@]}" ; do
        lHTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./s25_kernel_check.html@g")""linux-exploit-suggester""${LINK_END}"
        lLINK_COMMAND_ARR+=( "${lLES_LINE}""s@linux-exploit-suggester@""${lHTML_LINK}"'@' )
      done
    fi

    # Add anchors to link inside of modules
    if ( grep -a -q -E '\[ANC\]' "${lLINK_FILE}" ) ; then
      local lANC_ARR=()
      local lANC_NUMBER=""
      local lANC=""
      local lANC_LINE=""
      readarray -t lANC_ARR < <(grep -a -n -E '\[ANC\].*' "${lLINK_FILE}" | cut -d':' -f1 )
      for lANC_NUMBER in "${lANC_ARR[@]}" ; do
        lANC="$(sed "${lANC_NUMBER}""q;d" "${lLINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
        lANC_LINE="$(echo "${ANCHOR}" | sed -e "s@ANCHOR@anchor_${lANC}@g" || true)""${LINK_END}"
        lLINK_COMMAND_ARR+=( "${lANC_NUMBER}"'s@$@'"${lANC_LINE}"'@' )
      done
    fi

    # Exploit links and additional files
    if ( grep -a -q -E 'EDB ID:' "${lLINK_FILE}" ) ; then
      local lEXPLOITS_IDS=()
      local lEXPLOIT_ID=""
      local lEXPLOIT_ID_LINE=""
      local lEXPLOIT_ID_STRING=""
      local lEXPLOIT_FILE=""
      readarray -t lEXPLOITS_IDS < <( grep -a -n -o -E ".*EDB ID: ([0-9]*)[\ ]?*.*" "${lLINK_FILE}" | uniq || true)
      for lEXPLOIT_ID in "${lEXPLOITS_IDS[@]}" ; do
        lEXPLOIT_ID_LINE="$(echo "${lEXPLOIT_ID}" | cut -d ":" -f 1)"
        lEXPLOIT_ID_STRING="$(echo "${lEXPLOIT_ID}" | cut -d ":" -f 2-)"
        if [[ -n "${lEXPLOIT_ID_STRING}" ]] ; then
          lEXPLOIT_ID="$(echo "${lEXPLOIT_ID_STRING}" | grep -a -o -E "EDB ID: ([0-9]*)" | cut -d ":" -f 2 | sed -e 's/^[[:space:]]*//' || true)"
          lEXPLOIT_FILE="${LOG_DIR}""/f20_vul_aggregator/exploit/""${lEXPLOIT_ID}"".txt"
          if [[ -f "${lEXPLOIT_FILE}" ]] ; then
            # generate exploit file
            generate_info_file "${lEXPLOIT_FILE}" "${lBACK_LINK}" &
            lWAIT_PIDS_WR+=( "$!" )
            lHTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${lBACK_LINK}" | cut -d"." -f1 )/${lEXPLOIT_ID}.html@g")""${lEXPLOIT_ID}""${LINK_END}"
          else
            lHTML_LINK="$(echo "${EXPLOIT_LINK}" | sed -e "s@LINK@${lEXPLOIT_ID}@g")""${lEXPLOIT_ID}""${LINK_END}"
          fi
          lLINK_COMMAND_ARR+=( "${lEXPLOIT_ID_LINE}"'s@'"${lEXPLOIT_ID}"'@'"${lHTML_LINK}"'@' )
        fi
      done
    fi

    # MSF key links and additional files
    if ( grep -a -q -E 'Exploit.*MSF' "${lLINK_FILE}" ) ; then
      local lMSF_KEY_F=()
      local lMSF_KEY=""
      local lMSF_KEY_LINE=""
      local lMSF_KEY_STRING=""
      local lMSF_KEY_STRING_ARR=()
      local lMSF_KEY_ELEM=""
      local lMSF_KEY_FILE=""
      readarray -t lMSF_KEY_F < <( grep -a -n -o -E "MSF: (([0-9a-z_][\ ]?)+)*" "${lLINK_FILE}" | uniq || true)
      for lMSF_KEY in "${lMSF_KEY_F[@]}" ; do
        lMSF_KEY_LINE="$(echo "${lMSF_KEY}" | cut -d ":" -f 1)"
        lMSF_KEY_STRING="$(echo "${lMSF_KEY}" | cut -d ":" -f 3- | sed -e 's/^[[:space:]]*//')"
        readarray -t lMSF_KEY_STRING_ARR < <(echo "${lMSF_KEY_STRING}" | tr " " "\n" | uniq )
        for lMSF_KEY_ELEM in "${lMSF_KEY_STRING_ARR[@]}" ; do
          lMSF_KEY_FILE="${LOG_DIR}""/f20_vul_aggregator/exploit/msf_""${lMSF_KEY_ELEM}"".rb"
          if [[ -f "${lMSF_KEY_FILE}" ]] ; then
            # copy msf file
            local lRES_PATH=""
            lRES_PATH="${ABS_HTML_PATH}""/""$(echo "${lBACK_LINK}" | cut -d"." -f1 )""/res"
            if [[ ! -d "${lRES_PATH}" ]] ; then mkdir -p "${lRES_PATH}" > /dev/null || true; fi
            cp "${lMSF_KEY_FILE}" "${lRES_PATH}""/""$(basename "${lMSF_KEY_FILE}")" || true
            lHTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${lBACK_LINK}" | cut -d"." -f1 )/res/$(basename "${lMSF_KEY_FILE}")@g")""${lMSF_KEY_ELEM}""${LINK_END}"
            lLINK_COMMAND_ARR+=( "${lMSF_KEY_LINE}"'s@'"${lMSF_KEY_ELEM}"'@'"${lHTML_LINK}"'@' )
          fi
        done
      done
    fi

    if ( grep -a -q -E 'Exploit.*Snyk' "${lLINK_FILE}" ) ; then
      local lSNYK_KEY_F=()
      local lSNYK_KEY=""
      local lSNYK_ID_LINE=""
      local lSNYK_ID_STRING=""
      local lSNYK_KEY_STRING_ARR=()
      local lSNYK_KEY_ELEM=""
      readarray -t lSNYK_KEY_F < <( grep -a -n -o -E "Snyk: .*" "${lLINK_FILE}" | sed 's/Snyk: //' | uniq || true)
      for lSNYK_KEY in "${lSNYK_KEY_F[@]}" ; do
        lSNYK_ID_LINE="$(echo "${lSNYK_KEY}" | cut -d ":" -f 1)"
        lSNYK_ID_STRING="$(echo "${lSNYK_KEY}" | cut -d ":" -f 2-)"
        readarray -t lSNYK_KEY_STRING_ARR < <(echo "${lSNYK_ID_STRING}" | tr " " "\n" | grep "SNYK-" | uniq || true)
        for lSNYK_KEY_ELEM in "${lSNYK_KEY_STRING_ARR[@]}" ; do
          lHTML_LINK="$(echo "${SNYK_LINK}" | sed -e "s@LINKNAME@${lSNYK_KEY_ELEM}@g" | sed -e "s@LINK@${lSNYK_KEY_ELEM}@g")""${lSNYK_KEY_ELEM}""${LINK_END}"
          lLINK_COMMAND_ARR+=( "${lSNYK_ID_LINE}"'s@'"${lSNYK_KEY_ELEM}"'@'"${lHTML_LINK}"'@' )
        done
      done
    fi

    if ( grep -a -q -E 'Exploit.*PSS' "${lLINK_FILE}" ) ; then
      local lPSS_KEY_F=()
      local lPSS_KEY=""
      local lPSS_ID_LINE=""
      local lPSS_ID_STRING=""
      local lPSS_KEY_STRING_ARR=()
      local lPSS_KEY_NAME=""
      readarray -t lPSS_KEY_F < <( grep -a -n -o -E "PSS: .*" "${lLINK_FILE}" | sed 's/PSS: //' | uniq || true)
      for lPSS_KEY in "${lPSS_KEY_F[@]}" ; do
        lPSS_ID_LINE="$(echo "${lPSS_KEY}" | cut -d ":" -f 1)"
        lPSS_ID_STRING="$(echo "${lPSS_KEY}" | cut -d ":" -f 2-)"
        readarray -t lPSS_KEY_STRING_ARR < <(echo "${lPSS_ID_STRING}" | tr " " "\n" | grep -E "[0-9]+/.*\.html" | uniq || true)
        for lPSS_KEY_NAME in "${lPSS_KEY_STRING_ARR[@]}" ; do
          # lPSS_KEY_NAME="$(echo "${PSS_KEY_ELEM}" | tr "/" "_")"
          lHTML_LINK="$(echo "${PSS_LINK}" | sed -e "s@LINKNAME@${lPSS_KEY_NAME}@g" | sed -e "s@LINK@${lPSS_KEY_NAME}@g")""${lPSS_KEY_NAME}""${LINK_END}"
          lLINK_COMMAND_ARR+=( "${lPSS_ID_LINE}"'s@'"${lPSS_KEY_NAME}"'@'"${lHTML_LINK}"'@' )
        done
      done
    fi

    # CVE links
    if ( grep -a -q -E '(CVE)' "${lLINK_FILE}" ) ; then
      # in l35 html report we do not link CVE - we have Metasploit links in there
      local lCVE_IDS=()
      local lCVE_ID=""
      local lCVE_ID_LINE=""
      local lCVE_ID_STRING=""
      if ! [[ "${lLINK_FILE}" == *"l35_"* ]]; then
        readarray -t lCVE_IDS < <( grep -a -n -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' "${lLINK_FILE}" | uniq || true)
        for lCVE_ID in "${lCVE_IDS[@]}" ; do
          lCVE_ID_LINE="$(echo "${lCVE_ID}" | cut -d ":" -f 1)"
          lCVE_ID_STRING="$(echo "${lCVE_ID}" | cut -d ":" -f 2-)"
          if [[ -n "${lCVE_ID_STRING}" ]] ; then
            lHTML_LINK="$(echo "${CVE_LINK}" | sed -e "s@LINK@${lCVE_ID_STRING}@g")""${lCVE_ID_STRING}""${LINK_END}"
            if [[ "${lLINK_FILE}" == *"f20_vul_aggregator"* ]]; then
              lLINK_COMMAND_ARR+=( "${lCVE_ID_LINE}"'s@'"[[:blank:]]${lCVE_ID_STRING}"'@'"\t${lHTML_LINK}""@" )
            else
              lLINK_COMMAND_ARR+=( "${lCVE_ID_LINE}"'s@'"${lCVE_ID_STRING}"'@'"${lHTML_LINK}"'@' )
            fi
          fi
        done
      fi
    fi

    # CWE links
    if ( grep -a -q -E '(CWE)' "${lLINK_FILE}" ) ; then
      local lCWE_IDS=()
      local lCWE_ID=""
      local lCWE_ID_LINE=""
      local lCWE_ID_STRING=""
      local lCWE_ID_NUMBER=""
      readarray -t lCWE_IDS < <( grep -a -n -E -o 'CWE[0-9]{3,4}' "${lLINK_FILE}" | uniq || true)
      for lCWE_ID in "${lCWE_IDS[@]}" ; do
        lCWE_ID_LINE="$(echo "${lCWE_ID}" | cut -d ":" -f 1)"
        lCWE_ID_STRING="$(echo "${lCWE_ID}" | cut -d ":" -f 2-)"
        lCWE_ID_NUMBER="${lCWE_ID_STRING:3}"
        if [[ -n "${lCWE_ID_STRING}" ]] ; then
          lHTML_LINK="$(echo "${CWE_LINK}" | sed -e "s@LINK@${lCWE_ID_NUMBER}@g")""${lCWE_ID_STRING}""${LINK_END}"
          lLINK_COMMAND_ARR+=( "${lCWE_ID_LINE}"'s@'"${lCWE_ID_STRING}"'@'"${lHTML_LINK}"'@' )
        fi
      done
    fi

    # License links
    if ( grep -a -q -E 'License: ' "${lLINK_FILE}" ) ; then
      local lLIC_CODE_ARR=()
      local lLIC_URL_ARR=()
      while read -r LICENSE_LINK_LINE; do
        if echo "${LICENSE_LINK_LINE}" | grep -v -q "^[^#*/;]"; then
          continue
        fi
        lLIC_CODE_ARR=( "${lLIC_CODE_ARR[@]}" "$(echo "${LICENSE_LINK_LINE}" | cut -d';' -f1)")
        lLIC_URL_ARR=( "${lLIC_URL_ARR[@]}" "$(echo "${LICENSE_LINK_LINE}" | cut -d';' -f2-)")
      done  < "${CONFIG_DIR}"/bin_version_strings_links.cfg

      local lLICENSE_LINES=()
      local lLICENSE_LINE=""
      local lLICENSE_LINE_NUM=""
      local lLICENSE_STRING=""

      readarray -t lLICENSE_LINES < <( grep -a -n -E -o 'License: .*$' "${lLINK_FILE}" | uniq)
      for lLICENSE_LINE in "${lLICENSE_LINES[@]}" ; do
        lLICENSE_LINE_NUM="$(echo "${lLICENSE_LINE}" | cut -d: -f1)"
        lLICENSE_STRING="$(echo "${lLICENSE_LINE}" | cut -d: -f3 | sed -e 's/<[^>]*>//g' )"
        local lLIC_URL=""
        local lI=""
        for lI in "${!lLIC_CODE_ARR[@]}" ; do
          if [[ "${lLIC_CODE_ARR[${lI}]}" == "${lLICENSE_STRING:1}" ]] ; then
            lLIC_URL="${lLIC_URL_ARR[${lI}]}"
          fi
        done
        if [[ -n "${lLIC_URL}" ]] ; then
          lHTML_LINK="$(echo "${LICENSE_LINK}" | sed -e "s@LINK@${lLIC_URL}@g")""${lLICENSE_STRING:1}""${LINK_END}"
          lLINK_COMMAND_ARR+=( "${lLICENSE_LINE_NUM}"'s@'"${lLICENSE_STRING:1}"'@'"${lHTML_LINK}"'@' )
        fi
      done
    fi

    # [LOV] anchor for JS popup messages - Todo!
    if ( grep -a -q -E '\[LOV\]' "${lLINK_FILE}" ) ; then
      local lLOV_LINKS_L_NUMBER=()
      local lLOV_LINK=""
      local lLOV_LINK_NUMBER=""
      local lLOV_LINE_BEFORE=""
      readarray -t lLOV_LINKS_L_NUMBER < <(grep -a -n -E '\[LOV\].*' "${lLINK_FILE}" | cut -d':' -f1 )
      for lLOV_LINK_NUMBER in "${lLOV_LINKS_L_NUMBER[@]}" ; do
        DEPTH="."
        lLOV_LINK="$(sed "${lLOV_LINK_NUMBER}""q;d" "${lLINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
        if [[ -f "$(echo "${lLOV_LINK}" | cut -d"#" -f1)" ]] ; then
          echo "LOV_LINK: ${lLOV_LINK}"
          lLINE_NUMBER_INFO_PREV="$(( lLOV_LINK_NUMBER - 1 ))"
          while [[ ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}")" == "${BR}" ) ]] ; do
            lLINE_NUMBER_INFO_PREV=$(( lLINE_NUMBER_INFO_PREV - 1 ))
            echo "X lLINE_NUMBER_INFO_PREV: ${lLINE_NUMBER_INFO_PREV}"
          done
          lLOV_LINE_BEFORE="$(sed "${lLINE_NUMBER_INFO_PREV}""q;d" "${lLINK_FILE}" || true)"
          # lHTML_LINK="$(echo "${lLOV_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${lBACK_LINK}" | cut -d"." -f1)/$(basename "${lLOV_LINK%."${LOV_LINK##*.}"}").html@g" || true)"
          lHTML_LINK="$(echo "${LOCAL_OVERLAY_LINK}" | sed -e "s@LINK@${lLOV_LINK}@g" || true)"
          echo "lHTML_LINK: ${lHTML_LINK}"
          echo "lLOV_LINE_BEFORE: ${lLOV_LINE_BEFORE}"
          echo "lLINE_NUMBER_INFO_PREV: ${lLINE_NUMBER_INFO_PREV}"
          lLINK_COMMAND_ARR+=( "${lLINE_NUMBER_INFO_PREV}"'s@^@'"${lHTML_LINK}"'@' "${lLINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
          echo "LINK_COMMAND_ARR: ${lLINK_COMMAND_ARR[*]}"
        fi
      done
    fi
  fi

  if [[ "${#lLINK_COMMAND_ARR[@]}" -gt 0 ]] ; then
    if [[ -f "${lLINK_FILE}" ]]; then
      local lINSERT_ARR=()
      local lLOCAL_ARR=()
      local lINSERT_SIZE=100
      local lLINE=""
      local lSED_ERROR=""
      disable_strict_mode "${STRICT_MODE}" 0
      for (( X=0; X<${#lLINK_COMMAND_ARR[@]}; X++ )) ; do
        lLOCAL_ARR+=("${lLINK_COMMAND_ARR[${X}]}")
        lINSERT_ARR+=('-e' "${lLINK_COMMAND_ARR[${X}]}")
        if [[ ( ( $((X%lINSERT_SIZE)) -eq 0 ) && ${X} -ne 0 ) || ( $((${#lLINK_COMMAND_ARR[@]}-1)) -eq ${X} ) ]] ; then
          lSED_ERROR="$(sed -i "${lINSERT_ARR[@]}" "${lLINK_FILE}" 2>&1 >/dev/null)"
          if [[ -n "${lSED_ERROR}" ]] ; then
            printf "ERROR:\nInsertion of Chunk failed:\n%s\n\nError message:\n%s\n" "${lINSERT_ARR[@]}" "${lSED_ERROR}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${lLINK_FILE}").txt"
            lSED_ERROR=""
            printf "SINGLE_INSERTION:\n" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${lLINK_FILE}").txt"
            for lLINE in "${lLOCAL_ARR[@]}" ; do
              printf "%s\n" "${lLINE}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${lLINK_FILE}").txt"
              lSED_ERROR=$(sed -i "${lLINE}" "${lLINK_FILE}" 2>&1 >/dev/null)
              if [[ -n "${lSED_ERROR}" ]] ; then
                printf "ERROR:\nInsertion of single link failed:\n%s\n" "${lSED_ERROR}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${lLINK_FILE}").txt"
              fi
            done
          fi
          lINSERT_ARR=()
          lLOCAL_ARR=()
          lSED_ERROR=""
        fi
      done
      enable_strict_mode "${STRICT_MODE}" 0
    fi
  fi

  wait_for_pid "${lWAIT_PIDS_WR[@]}"
  if [[ -f "${lLINK_FILE}" ]]; then
    sed -i -E 's@^<pre>((\[REF\])|(\[ANC\])).*</pre>@@g' "${lLINK_FILE}" || true
  fi
}

strip_color_tags() {
  echo "${1:-}" | sed 's@\x1b\[[0-9;]*m@@g' | tr -d '\000-\010\013\014\016-\037'
}

# often we have additional information, like exploits or cve's
generate_info_file() {
  local lINFO_FILE=${1:-}
  local lSRC_FILE=${2:-}
  local lCUSTOM_SUB_PATH=${3:-}

  local lDEPTH_HTML_HEADER="./.."
  local lINFO_PATH=""
  local lSRC_FILE_NAME=""

  local lINFO_HTML_FILE=""
  lINFO_HTML_FILE="$(basename "${lINFO_FILE%."${lINFO_FILE##*.}"}"".html")"

  # extract just the log directory name of the module:
  # export vs local?
  export LOG_DIR_MODULE=""
  LOG_DIR_MODULE="$(echo "${LOG_PATH_MODULE}" | sed -e "s#""${LOG_DIR}""##g")"
  LOG_DIR_MODULE="${LOG_DIR_MODULE//\/}"
  lSRC_FILE_NAME="$(echo "${lSRC_FILE}" | cut -d"." -f1 )"

  if [[ -z "${lCUSTOM_SUB_PATH}" ]] ; then
    if [[ "${LOG_DIR_MODULE}" !=  "${lSRC_FILE_NAME}" ]]; then
      lINFO_PATH="${ABS_HTML_PATH}/${LOG_DIR_MODULE}/${lSRC_FILE_NAME}"
      # INFO: now we have another directory depth and we need to adjust the html header
      lDEPTH_HTML_HEADER="./../.."
    else
      lINFO_PATH="${ABS_HTML_PATH}/${LOG_DIR_MODULE}"
      lDEPTH_HTML_HEADER="./.."
    fi
  else
    lINFO_PATH="${ABS_HTML_PATH}/${LOG_DIR_MODULE}/""${lCUSTOM_SUB_PATH}"
  fi

  local lRES_PATH="${lINFO_PATH}""/res"

  if ! [[ -d "${lINFO_PATH}" ]]; then
    mkdir -p "${lINFO_PATH}" || true
  fi

  if [[ ! -f "${lINFO_PATH}""/""${lINFO_HTML_FILE}" ]] && [[ -f "${lINFO_FILE}" ]] ; then
    cp "./helpers/base.html" "${lINFO_PATH}""/""${lINFO_HTML_FILE}" || true
    sed -i -e "s:\.\/:""${lDEPTH_HTML_HEADER}""/:g" "${lINFO_PATH}""/""${lINFO_HTML_FILE}"

    local lSUB_PATH=""
    lSUB_PATH="$(dirname "$(echo "${lINFO_FILE}" | sed -e "s#""${LOG_DIR}""##g")")"
    local lTMP_INFO_FILE="${ABS_HTML_PATH}""${TEMP_PATH}""/""${lSUB_PATH}""/""${lINFO_HTML_FILE}"
    local lTMP_INFO_DIR="${ABS_HTML_PATH}""${TEMP_PATH}""/""${lSUB_PATH}"

    # add back Link anchor to navigation
    if [[ -n "${lSRC_FILE}" ]] ; then
      local lLINE_NUMBER_INFO_NAV=""
      local lNAV_INFO_BACK_LINK=""
      lLINE_NUMBER_INFO_NAV=$(grep -a -n "navigation start" "${lINFO_PATH}""/""${lINFO_HTML_FILE}" | cut -d":" -f1 || true)
      lNAV_INFO_BACK_LINK="$(echo "${MODUL_LINK}" | sed -e "s@LINK@./../${lSRC_FILE}@g")"
      sed -i "${lLINE_NUMBER_INFO_NAV}""i""${lNAV_INFO_BACK_LINK}""&laquo; Back to ""$(basename "${lSRC_FILE%.html}")""${LINK_END}" "${lINFO_PATH}""/""${lINFO_HTML_FILE}"
    fi

    ! [[ -d "${lTMP_INFO_DIR}" ]] && mkdir -p "${lTMP_INFO_DIR}"
    cp "${lINFO_FILE}" "${lTMP_INFO_FILE}" 2>/dev/null || true

    sed -i -e 's@&@\&amp;@g ; s/@/\&commat;/g ; s@<@\&lt;@g ; s@>@\&gt;@g' "${lTMP_INFO_FILE}" || true
    sed -i '\@\[\*\]\ Statistics@d' "${lTMP_INFO_FILE}" || true

    sed -i -e "s:^:${P_START}: ; s:$:${P_END}:" "${lTMP_INFO_FILE}" || true
    # add html tags for style
    add_color_tags "${lTMP_INFO_FILE}"
    sed -i -e "s:[=]{65}:${HR_DOUBLE}:g ; s:^[-]{65}$:${HR_MONO}:g" "${lTMP_INFO_FILE}" || true

    # add link tags to links/generate info files and link to them and write line to tmp file
    add_link_tags "${lTMP_INFO_FILE}" "${lINFO_HTML_FILE}"

    local lEXPLOITS_IDS_INFO_ARR=()
    local lEXPLOIT_ID_INFO=""
    readarray -t lEXPLOITS_IDS_INFO_ARR < <( grep -a 'Exploit DB Id:' "${lINFO_FILE}" | sed -e 's@[^0-9\ ]@@g ; s@\ @@g' | sort -u || true)
    for lEXPLOIT_ID_INFO in "${lEXPLOITS_IDS_INFO_ARR[@]}" ; do
      local lONLINE=""
      lONLINE="$(echo "${EXPLOIT_LINK}" | sed -e "s@LINK@${lEXPLOIT_ID_INFO}@g" || true)""${lEXPLOIT_ID_INFO}""${LINK_END}"
      printf "%s%sOnline: %s%s\n" "${HR_MONO}" "${P_START}" "${lONLINE}" "${P_END}" >> "${lTMP_INFO_FILE}"
    done

    local lEXPLOIT_FILES_ARR=()
    local lE_PATH=""
    local lE_HTML_LINK=""
    readarray -t lEXPLOIT_FILES_ARR < <(grep -a "File: " "${lINFO_FILE}" | cut -d ":" -f 2 | sed 's@^\ @@' | sort -u || true)
    for lE_PATH in "${lEXPLOIT_FILES_ARR[@]}" ; do
      if [[ -f "${lE_PATH}" ]] ; then
        if [[ ! -d "${lRES_PATH}" ]] ; then mkdir -p "${lRES_PATH}" > /dev/null || true ; fi
        cp "${lE_PATH}" "${lRES_PATH}""/""$(basename "${lE_PATH}")" || true
        lE_HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./res/$(basename "${lE_PATH}")@g")""$(basename "${lE_PATH}")""${LINK_END}"
        printf "%s%sFile: %s%s\n" "${HR_MONO}" "${P_START}" "${lE_HTML_LINK}" "${P_END}" >> "${lTMP_INFO_FILE}"
      fi
    done

    # add content of temporary html into template
    sed -i "/content start/ r ${lTMP_INFO_FILE}" "${lINFO_PATH}""/""${lINFO_HTML_FILE}"
  fi
}

generate_report_file() {
  local lREPORT_FILE=${1:-}
  # if set to 1, then generate file in supplementary folder and link to menu
  local lSUPPL_FILE_GEN=${2:-}

  local lMODUL_NAME=""
  local lSUBMODUL_NAMES_ARR=()
  local lSUBMODUL_NAME=""
  local lLINE_NUMBER_REP_NAV=""
  local lSUB_NAV_LINK=""
  local lA_SUBMODUL_NAME=""
  local lLINE=""
  local lHTML_FILE=""
  if ! ( grep -a -o -i -q "$(basename "${lREPORT_FILE%."${lREPORT_FILE##*.}"}")"" nothing reported" "${lREPORT_FILE}" ) ; then
    lHTML_FILE="$(basename "${lREPORT_FILE%."${lREPORT_FILE##*.}"}"".html" 2>/dev/null || true)"
    if [[ ${lSUPPL_FILE_GEN} -eq 1 ]] ; then
      cp "./helpers/base.html" "${ABS_HTML_PATH%/}/${SUPPL_PATH_HTML}/${lHTML_FILE}" || true
    else
      cp "./helpers/base.html" "${ABS_HTML_PATH%/}/${lHTML_FILE}" || true
    fi
    local lTMP_FILE="${ABS_HTML_PATH%/}/${TEMP_PATH}/${lHTML_FILE}"
    if [[ ! -d "${ABS_HTML_PATH%/}/${TEMP_PATH}" ]]; then
      mkdir "${ABS_HTML_PATH%/}/${TEMP_PATH}"
    fi

    # parse log content and add to html file
    lLINE_NUMBER_REP_NAV=$(grep -a -n "navigation start" "${ABS_HTML_PATH%/}/${lHTML_FILE}" | cut -d":" -f1)

    cp "${lREPORT_FILE}" "${lTMP_FILE}" || true
    sed -i -e 's@&@\&amp;@g ; s/@/\&commat;/g ; s@<@\&lt;@g ; s@>@\&gt;@g' "${lTMP_FILE}"
    sed -i '\@\[\*\]\ Statistics@d' "${lTMP_FILE}"

    # module title anchor links
    if ( grep -a -q -E '[=]{65}' "${lTMP_FILE}" ) ; then
      lMODUL_NAME="$( strip_color_tags "$(grep -a -E -B 1 '[=]{65}' "${lTMP_FILE}" | head -n 1 )" | cut -d" " -f2- )"
      local lA_MODUL_NAME=""
      if [[ -n "${lMODUL_NAME}" ]] ; then
        # add anchor to file
        lA_MODUL_NAME="$(echo "${lMODUL_NAME}" | sed -e "s@\ @_@g" | tr "[:upper:]" "[:lower:]")"
        lLINE="$(echo "${TITLE_ANCHOR}" | sed -e "s@ANCHOR@${lA_MODUL_NAME}@g")""${lMODUL_NAME}""${LINK_END}"
        sed -i -E "s@${lMODUL_NAME}@${lLINE}@" "${lTMP_FILE}" || true
        # add link to index navigation
        add_link_to_index "${lHTML_FILE}" "${lMODUL_NAME}"
        # add module anchor to navigation
        NAV_LINK="$(echo "${MODUL_LINK}" | sed -e "s@LINK@#${lA_MODUL_NAME}@g")"
        sed -i "${lLINE_NUMBER_REP_NAV}"'s@$@'"${NAV_LINK}""${lMODUL_NAME}""${LINK_END}"'@' "${ABS_HTML_PATH}""/""${lHTML_FILE}"
      fi
    fi

    # submodule title anchor links
    if ( grep -a -q -E '^[-]{65}$' "${lTMP_FILE}" ) ; then
      readarray -t lSUBMODUL_NAMES_ARR < <( grep -a -E -B 1 '^[-]{65}$' "${lTMP_FILE}" | sed -E '\@[-]{65}@d' | grep -a -v "^--")
      for lSUBMODUL_NAME in "${lSUBMODUL_NAMES_ARR[@]}" ; do
        if [[ -n "${lSUBMODUL_NAME}" ]] ; then
          lSUBMODUL_NAME="$( strip_color_tags "${lSUBMODUL_NAME}" | cut -d" " -f 2- )"
          lA_SUBMODUL_NAME="$(echo "${lSUBMODUL_NAME}" | sed -e "s@[^a-zA-Z0-9]@@g" | tr "[:upper:]" "[:lower:]")"
          lLINE="$(echo "${TITLE_ANCHOR}" | sed -e "s@ANCHOR@${lA_SUBMODUL_NAME}@g")""${lSUBMODUL_NAME}""${LINK_END}"
          sed -i -E "s@${lSUBMODUL_NAME}@${lLINE}@" "${lTMP_FILE}" || true
          # Add anchor to file
          lSUB_NAV_LINK="$(echo "${SUBMODUL_LINK}" | sed -e "s@LINK@#${lA_SUBMODUL_NAME}@g")"
          sed -i "${lLINE_NUMBER_REP_NAV}"'s@$@'"${lSUB_NAV_LINK}""${lSUBMODUL_NAME}""${LINK_END}"'@' "${ABS_HTML_PATH}""/""${lHTML_FILE}"
        fi
      done
    fi

    sed -i -E -e "s:[=]{65}:${HR_DOUBLE}:g ; s:^[-]{65}$:${HR_MONO}:g" "${lTMP_FILE}" || true
    sed -i -e "s:^:${P_START}: ; s:$:${P_END}:" "${lTMP_FILE}" || true
    # this fixes the </pre> lines instead of <pre></pre> - something weird with \r\n
    sed -i -E "s:\r${P_END}:${P_END}:" "${lTMP_FILE}" || true

    # add html tags for style
    add_color_tags "${lTMP_FILE}"

    # add link tags to links/generate info files and link to them and write line to tmp file
    # also parsing for [REF] anchor and generate linked files and link it
    # to ignore all links except [REF], just add '1' as third parameter
    if [[ "$(basename "${lREPORT_FILE}" | cut -d "_" -f 1 )" == "s99" ]] ; then
      add_link_tags "${lTMP_FILE}" "${lHTML_FILE}" 1
    else
      add_link_tags "${lTMP_FILE}" "${lHTML_FILE}"
    fi

    # add content of temporary html into template
    if [[ ${lSUPPL_FILE_GEN} -eq 1 ]] ; then
      sed -i "/content start/ r ${lTMP_FILE}" "${ABS_HTML_PATH}${SUPPL_PATH_HTML}""/""${lHTML_FILE}"
    else
      sed -i "/content start/ r ${lTMP_FILE}" "${ABS_HTML_PATH}""/""${lHTML_FILE}"
    fi
    # add aggregator lines to index page
    if [[ "${lHTML_FILE}" == "f50"* ]] ; then
      sed -i "/content start/ r ${lTMP_FILE}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
    fi
  fi
}

add_link_to_index() {
  insert_line() {
    local lSEARCH_VAL="${1:-}"
    local lMODUL_NAME="${2:-}"
    local lCLASS="${3:-}"
    local lDATA="${4:-}"

    local lLINE_NUMBER_NAV_INSERT=""
    local lREP_NAV_LINK=""

    lLINE_NUMBER_NAV_INSERT=$(grep -a -m 1 -n "${lSEARCH_VAL}" "${ABS_HTML_PATH}""/""${INDEX_FILE}" | cut -d ":" -f 1)
    lREP_NAV_LINK="$(echo "${MODUL_INDEX_LINK}" | sed -e "s@LINK@.\/${HTML_FILE}@g" | sed -e "s@CLASS@${lCLASS}@g" | sed -e "s@DATA@${lDATA}@g")"
    sed -i "${lLINE_NUMBER_NAV_INSERT}""i""${lREP_NAV_LINK}""${lMODUL_NAME}""${LINK_END}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  }

  HTML_FILE="${1:-}"
  local lMODUL_NAME="${2:-}"
  local lDATA=""
  local lCLASS=""
  local lC_NUMBER=""
  local lINDEX_NAV_GROUP_ARR=()
  local lINDEX_NAV_ARR=()

  lDATA="$( echo "${HTML_FILE}" | cut -d "_" -f 1)"
  lCLASS="${lDATA:0:1}"
  lC_NUMBER="$(echo "${lDATA:1}" | sed -E 's@^0*@@g')"

  readarray -t lINDEX_NAV_ARR < <(sed -n -e '/navigation start/,/navigation end/p' "${ABS_HTML_PATH}""/""${INDEX_FILE}" | sed -e '1d;$d' | grep -a -P -o '(?<=data=\").*?(?=\")' || true)
  readarray -t lINDEX_NAV_GROUP_ARR < <(printf -- '%s\n' "${lINDEX_NAV_ARR[@]}" | grep -a "${lCLASS}" || true)

  if [[ ${#lINDEX_NAV_GROUP_ARR[@]} -eq 0 ]] ; then
    # due the design of EMBA, which are already groups the modules (even threaded), it isn't necessary to check -
    # insert new entry at bottom of the navigation
    insert_line "navigation end" "${lMODUL_NAME}" "${lCLASS}" "${lDATA}"
  else
    for (( COUNT=0; COUNT<=${#lINDEX_NAV_GROUP_ARR[@]}; COUNT++ )) ; do
      if [[ ${COUNT} -eq 0 ]] && [[ ${lC_NUMBER} -lt $( echo "${lINDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
        insert_line "${lINDEX_NAV_GROUP_ARR[${COUNT}]}" "${lMODUL_NAME}" "${lCLASS}" "${lDATA}"
        continue
      elif [[ ${COUNT} -eq $(( ${#lINDEX_NAV_GROUP_ARR[@]}-1 )) ]] && [[ ${lC_NUMBER} -gt $( echo "${lINDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
        insert_line "navigation end" "${lMODUL_NAME}" "${lCLASS}" "${lDATA}"
        continue
      fi
      # COUNT+1 is not available on the last element - we need to check the array for this:
      if [[ -v lINDEX_NAV_GROUP_ARR[${COUNT}] ]] && [[ -v lINDEX_NAV_GROUP_ARR[$((COUNT+1))] ]]; then
        if [[ ${lC_NUMBER} -gt $( echo "${lINDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] && [[ ${lC_NUMBER} -lt $( echo "${lINDEX_NAV_GROUP_ARR[$((COUNT+1))]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
          insert_line "${lINDEX_NAV_GROUP_ARR[$((COUNT+1))]}" "${lMODUL_NAME}" "${lCLASS}" "${lDATA}"
        fi
      fi
    done
  fi
}

update_index() {
  local lSUPPL_FILES_ARR=()
  local lS_FILE=""
  local lLINE_NUMBER_NAV=""
  local lREP_NAV_LINK=""

  # add emba.log to webreport
  generate_report_file "${MAIN_LOG}"
  sed -i -e "s@buttonTimeInvisible@buttonTime@ ; s@TIMELINK@.\/$(basename "${MAIN_LOG%."${MAIN_LOG##*.}"}"".html")@" "${ABS_HTML_PATH}""/""${INDEX_FILE}"

  # generate files in $SUPPL_PATH (supplementary files from modules)
  readarray -t lSUPPL_FILES_ARR < <(find "${SUPPL_PATH}" ! -path "${SUPPL_PATH}")
  if [[ "${#lSUPPL_FILES_ARR[@]}" -gt 0 ]] ; then
    sed -i 's@expand_njs hidden@expand_njs@g' "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  fi
  for lS_FILE in "${lSUPPL_FILES_ARR[@]}" ; do
    generate_info_file "${lS_FILE}" "" "${SUPPL_PATH_HTML}"
    lLINE_NUMBER_NAV=$(grep -a -n "etc start" "${ABS_HTML_PATH}""/""${INDEX_FILE}" | cut -d ":" -f 1)
    lREP_NAV_LINK="$(echo "${ETC_INDEX_LINK}" | sed -e "s@LINK@./${SUPPL_PATH_HTML}/$(basename "${lS_FILE%."${lS_FILE##*.}"}"".html")@g")"
    sed -i "${lLINE_NUMBER_NAV}""i""${lREP_NAV_LINK}""$(basename "${lS_FILE%."${lS_FILE##*.}"}")""${LINK_END}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  done
  scan_report
  add_arrows

  # remove tempory files from web report
  rm -R "${ABS_HTML_PATH}${TEMP_PATH}"
  rmdir "${ABS_HTML_PATH}${ERR_PATH}" 2>/dev/null || true
  rm -R "${ABS_HTML_PATH}"/qemu_init* 2>/dev/null || true
}

scan_report() {
  # at the end of an EMBA run, we have to disable all non-valid links to modules
  local lLINK_ARR=()
  readarray -t lLINK_ARR < <(grep -a -r -E "class\=\"refmodul\" href=\"(.*)" "${ABS_HTML_PATH}" | cut -d"\"" -f 4 | cut -d"#" -f 1 | sort -u || true)
  local lLINK_FILE_ARR=()
  local lLINK=""
  local lFILE=""
  readarray -t lLINK_FILE_ARR < <(grep -a -r -E -l "class\=\"refmodul\" href=\"(.*)" "${ABS_HTML_PATH}" || true)
  for lLINK in "${lLINK_ARR[@]}" ; do
    for lFILE in "${lLINK_FILE_ARR[@]}" ; do
      if ! [[ -f "${ABS_HTML_PATH}""/""${lLINK}" ]] ; then
        sed -i "s@class=\"refmodul\" href=\"(${lLINK})\"@@g" "${lFILE}"
      fi
    done
  done
}

add_arrows() {
  local lD_MODULE_ARR=()
  readarray -t lD_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./d[0-9]*.*" | sort -V || true)
  local lP_MODULE_ARR=()
  readarray -t lP_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./p[0-9]*.*" | sort -V || true)
  local lS_MODULE_ARR=()
  readarray -t lS_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./s[0-9]*.*" | sort -V || true)
  local lL_MODULE_ARR=()
  readarray -t lL_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./l[0-9]*.*" | sort -V || true)
  local lF_MODULE_ARR=()
  readarray -t lF_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./f[0-9]*.*" | sort -V || true)
  local lQ_MODULE_ARR=()
  readarray -t lQ_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./q[0-9]*.*" | sort -V || true)
  export ALL_MODULE_ARR=( "${ABS_HTML_PATH}""/""${INDEX_FILE}" "${lD_MODULE_ARR[@]}" "${lP_MODULE_ARR[@]}" "${lS_MODULE_ARR[@]}" "${lQ_MODULE_ARR[@]}" "${lL_MODULE_ARR[@]}" "${lF_MODULE_ARR[@]}")
  local lM_NUM=""

  local lLINE_NUMBER_A_BUTTON=""
  local lFIRST_LINK=""
  local lSECOND_LINK=""
  local lHTML_LINK=""
  for lM_NUM in "${!ALL_MODULE_ARR[@]}"; do
    if [[ "${lM_NUM}" -gt 0 ]] ; then
      lFIRST_LINK="${ALL_MODULE_ARR[$(( lM_NUM - 1 ))]}"
      lLINE_NUMBER_A_BUTTON=$(grep -a -m 1 -n "buttonForward" "${ALL_MODULE_ARR[${lM_NUM}]}" | cut -d ":" -f 1 || true)
      lHTML_LINK="$(echo "${ARROW_LINK}" | sed -e "s@LINK@./""$(basename "${lFIRST_LINK}")""@g")"
      sed -i -e "${lLINE_NUMBER_A_BUTTON}"'s@^@'"${lHTML_LINK}"'@' -e "${lLINE_NUMBER_A_BUTTON}"'s@$@'"${LINK_END}"'@' -e "${lLINE_NUMBER_A_BUTTON}""s@nonClickable @@" -e "${lLINE_NUMBER_A_BUTTON}""s@stroke=\"#444\"@stroke=\"#fff\"@" "${ALL_MODULE_ARR[${lM_NUM}]}" || true
    fi
    if [[ "$(( lM_NUM + 1 ))" -lt "${#ALL_MODULE_ARR[@]}" ]] ; then
      lSECOND_LINK="${ALL_MODULE_ARR[$(( lM_NUM + 1 ))]}"
      lLINE_NUMBER_A_BUTTON=$(grep -a -m 1 -n "buttonBack" "${ALL_MODULE_ARR[${lM_NUM}]}" | cut -d ":" -f 1 || true)
      lHTML_LINK="$(echo "${ARROW_LINK}" | sed -e "s@LINK@./""$(basename "${lSECOND_LINK}")""@g")"
      sed -i -e "${lLINE_NUMBER_A_BUTTON}"'s@^@'"${lHTML_LINK}"'@' -e "${lLINE_NUMBER_A_BUTTON}"'s@$@'"${LINK_END}"'@' -e "${lLINE_NUMBER_A_BUTTON}""s@nonClickable @@" -e "${lLINE_NUMBER_A_BUTTON}""s@stroke=\"#444\"@stroke=\"#fff\"@" "${ALL_MODULE_ARR[${lM_NUM}]}" || true
    fi
  done
}

prepare_report() {
  export ABS_HTML_PATH=""
  ABS_HTML_PATH="$(abs_path "${HTML_PATH}")"

  if [ ! -d "${ABS_HTML_PATH}${STYLE_PATH}" ] ; then
    mkdir -p "${ABS_HTML_PATH}${STYLE_PATH}" || true
    cp "${HELP_DIR}/style.css" "${ABS_HTML_PATH}${STYLE_PATH}/style.css" || true
    cp "${HELP_DIR}/emba.svg" "${ABS_HTML_PATH}${STYLE_PATH}/emba.svg" || true
    cp "${HELP_DIR}/embark.svg" "${ABS_HTML_PATH}${STYLE_PATH}/embark.svg" || true
    cp "${HELP_DIR}/favicon.png" "${ABS_HTML_PATH}${STYLE_PATH}/favicon.png" || true
  fi
  if [ ! -d "${ABS_HTML_PATH}${TEMP_PATH}" ] ; then
    mkdir -p "${ABS_HTML_PATH}${TEMP_PATH}" || true
  fi
  if [ ! -d "${ABS_HTML_PATH}${ERR_PATH}" ] ; then
    mkdir -p "${ABS_HTML_PATH}${ERR_PATH}" || true
  fi
  if [ ! -d "${ABS_HTML_PATH}${SUPPL_PATH_HTML}" ] ; then
    mkdir -p "${ABS_HTML_PATH}${SUPPL_PATH_HTML}" || true
  fi

  cp "./helpers/base.html" "${ABS_HTML_PATH}""/""${INDEX_FILE}" || true
  sed -i 's@backButton@backButton hidden@g' "${ABS_HTML_PATH}""/""${INDEX_FILE}"
}
