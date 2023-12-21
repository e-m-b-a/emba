#!/bin/bash -p
# shellcheck disable=SC2001

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Pascal Eckmann,
# Contributors: Michael Messner, Stefan Haboeck

INDEX_FILE="index.html"
MAIN_LOG="./emba.log"
STYLE_PATH="/style"
TEMP_PATH="/tmp"
ERR_PATH="/err"
SUPPL_PATH_HTML="/etc"

# variables for html style
P_START="<pre>"
P_END="</pre>"
SPAN_RED="<span class=\"red\">"
SPAN_GREEN="<span class=\"green\">"
SPAN_ORANGE="<span class=\"orange\">"
SPAN_BLUE="<span class=\"blue\">"
SPAN_MAGENTA="<span class=\"magenta\">"
SPAN_CYAN="<span class=\"cyan\">"
SPAN_BOLD="<span class=\"bold\">"
SPAN_ITALIC="<span class=\"italic\">"
SPAN_END="</span>"
HR_MONO="<hr class=\"mono\" />"
HR_DOUBLE="<hr class=\"double\" />"
BR="<br />"
LINK="<a href=\"LINK\" title=\"LINK\" target=\"_blank\" >"
ARROW_LINK="<a href=\"LINK\" title=\"LINK\" >"
LOCAL_LINK="<a class=\"local\" href=\"LINK\" title=\"LINK\" >"
REFERENCE_LINK="<a class=\"reference\" href=\"LINK\" title=\"LINK\" >"
REFERENCE_MODUL_LINK="<a class=\"refmodul\" href=\"LINK\" title=\"LINK\" >"
LOCAL_OVERLAY_LINK="<a class=\"refmodul\" onclick=\"overlay_output\(\"LINK\"\) >"
REFERENCE_MODUL_EXT_LINK="<a class=\"refmodulext\" href=\"LINK\" title=\"LINK\" target=\"_blank\">"
EXPLOIT_LINK="<a href=\"https://www.exploit-db.com/exploits/LINK\" title=\"LINK\" target=\"_blank\" >"
CVE_LINK="<a href=\"https://nvd.nist.gov/vuln/detail/LINK\" title=\"LINK\" target=\"_blank\" >"
CWE_LINK="<a href=\"https://cwe.mitre.org/data/definitions/LINK.html\" title=\"LINK\" target=\"_blank\" >"
GITHUB_LINK="<a href=\"https://github.com/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
SNYK_LINK="<a href=\"https://security.snyk.io/vuln/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
PSS_LINK="<a href=\"https://packetstormsecurity.com/files/LINK\" title=\"LINKNAME\" target=\"_blank\" >"
LICENSE_LINK="<a href=\"LINK\" title=\"LINK\" target=\"_blank\" >"
MODUL_LINK="<a class=\"modul\" href=\"LINK\" title=\"LINK\" >"
MODUL_INDEX_LINK="<a class=\"modul CLASS\" data=\"DATA\" href=\"LINK\" title=\"LINK\">"
ETC_INDEX_LINK="<a class=\"etc\" href=\"LINK\" title=\"LINK\">"
SUBMODUL_LINK="<a class=\"submodul\" href=\"LINK\" title=\"LINK\" >"
ANCHOR="<a class=\"anc\" id=\"ANCHOR\">"
TITLE_ANCHOR="<a id=\"ANCHOR\">"
LINK_END="</a>"
DEPTH="."
ARACHNI_LINK="<a href=\"./l25_web_checks/arachni_report/index.html\" title=\"Arachni web report\" target=\"_blank\" >"


add_color_tags()
{
  COLOR_FILE="${1:-}"
  sed -i -E \
    -e 's@\x1b\[@;@g ; s@;[0-9]{0};@;00;@g ; s@;([0-9]{1});@;0\1;@g ; s@;([0-9]{2});@;\1;@g ' \
    -e 's@;([0-9]{0})(m){1}@;00@g ; s@;([0-9]{1})(m){1}@;0\1@g ; s@;([0-9]{2})(m){1}@;\1@g ' \
    -e "s@;31@${SPAN_RED}@g ; s@;32@${SPAN_GREEN}@g ; s@;33@${SPAN_ORANGE}@g" \
    -e "s@;34@${SPAN_BLUE}@g ; s@;35@${SPAN_MAGENTA}@g ; s@;36@${SPAN_CYAN}@g" \
    -e "s@;01@${SPAN_BOLD}@g ; s@;03@${SPAN_ITALIC}@g ; s@;00@${SPAN_END}@g" \
    -e "s@;[0-9]{2}@@g ; s@${P_START}${P_END}@${BR}@g" "${COLOR_FILE}" || true
}

add_link_tags() {
  local LINK_FILE
  LINK_FILE="${1:-}"
  local BACK_LINK
  BACK_LINK="${2:-}"
  # If a module generates for example a list with links to referenced files ([REF]-tag), you don't want additional links in this list
  # set the third parameter to '1' to only generate [REF] links
  local IGNORE_LINKS
  IGNORE_LINKS="${3:-0}"

  local LINK_COMMAND_ARR
  LINK_COMMAND_ARR=()
  local WAIT_PIDS_WR=()

  # [REF] anchor
  if ( grep -a -q -E '\[REF\]' "${LINK_FILE}" ) ; then
    readarray -t REF_LINKS_L_NUMBER < <(grep -a -n -E '\[REF\].*' "${LINK_FILE}" | cut -d':' -f1 )
    # print_output "[*] REF link found in ${LINK_FILE}" "no_log"
    for REF_LINK_NUMBER in "${REF_LINKS_L_NUMBER[@]}" ; do
      DEPTH="."
      REF_LINK="$(sed "${REF_LINK_NUMBER}""q;d" "${LINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
      URL_REGEX='(www.|https?|ftp|file):\/\/'
      if [[ -f "$(echo "${REF_LINK}" | cut -d"#" -f1)" ]] ; then
        if [[  ( ("${REF_LINK: -4}" == ".txt") || ("${REF_LINK: -4}" == ".log") ) || ( ("${REF_LINK}" == *".txt#"*) || ("${REF_LINK}" == *".log#"*) || ("${REF_LINK: -2}" == ".c") ) ]] ; then
          REF_ANCHOR=""
          if [[ ( ("${REF_LINK}" == *".txt#"*) || ("${REF_LINK}" == *".log#"*) ) ]] ; then
            REF_ANCHOR="$(echo "${REF_LINK}" | cut -d"#" -f2 || true)"
            REF_LINK="$(echo "${REF_LINK}" | cut -d"#" -f1 || true)"
          fi
          # generate reference file
          generate_info_file "${REF_LINK}" "${BACK_LINK}" &
          WAIT_PIDS_WR+=( "$!" )

          if [[ -n "${REF_ANCHOR}" ]] ; then
            HTML_LINK="$(echo "${REFERENCE_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${BACK_LINK}" | cut -d"." -f1)/$(basename "${REF_LINK%."${REF_LINK##*.}"}").html""#anchor_${REF_ANCHOR}@g" || true)"
          else
            HTML_LINK="$(echo "${REFERENCE_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${BACK_LINK}" | cut -d"." -f1)/$(basename "${REF_LINK%."${REF_LINK##*.}"}").html@g" || true)"
          fi
          LINE_NUMBER_INFO_PREV="$(( REF_LINK_NUMBER - 1 ))"
          while [[ ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${BR}" ) ]] ; do
            LINE_NUMBER_INFO_PREV=$(( LINE_NUMBER_INFO_PREV - 1 ))
          done
          LINK_COMMAND_ARR+=( "${LINE_NUMBER_INFO_PREV}"'s@^@'"${HTML_LINK}"'@' "${LINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
        elif [[ "${REF_LINK: -7}" == ".tar.gz" ]] ; then
          local RES_PATH
          RES_PATH="${ABS_HTML_PATH}""/""$(echo "${BACK_LINK}" | cut -d"." -f1 )""/res"
          if [[ ! -d "${RES_PATH}" ]] ; then mkdir -p "${RES_PATH}" > /dev/null || true ; fi
          cp "${REF_LINK}" "${RES_PATH}""/""$(basename "${REF_LINK}")" || true
          HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${BACK_LINK}" | cut -d"." -f1 )/res/$(basename "${REF_LINK}")@g" || true)""Download Qemu emulation archive.""${LINK_END}"
          sed -i "s@Qemu emulation archive created in log directory.*$(basename "${REF_LINK}").*@${HTML_LINK}${P_END}@" "${LINK_FILE}"
        elif [[ "${REF_LINK: -4}" == ".png" ]] ; then
          LINE_NUMBER_INFO_PREV="$(grep -a -n -m 1 -E "\[REF\] ""${REF_LINK}" "${LINK_FILE}" | cut -d":" -f1 || true)"
          cp "${REF_LINK}" "${ABS_HTML_PATH}${STYLE_PATH}""/""$(basename "${REF_LINK}")" || true

          if [[ "$(echo "${REF_LINK}" | rev | cut -d '/' -f4- | rev)" == "${LOG_DIR}" ]]; then
            DEPTH=".."
          elif [[ "$(echo "${REF_LINK}" | rev | cut -d '/' -f3- | rev)" == "${LOG_DIR}" ]]; then
            DEPTH="."
          fi
          IMAGE_LINK="<img class=\"image\" src=\"${DEPTH}${STYLE_PATH}/PICTURE\">"
          HTML_LINK="$(echo "${IMAGE_LINK}" | sed -e 's@PICTURE@'"$(basename "${REF_LINK}")"'@' || true)"
          LINK_COMMAND_ARR+=( "${LINE_NUMBER_INFO_PREV}"'s@$@'"${HTML_LINK}"'@' )
        fi
      elif [[ ("${REF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}$ ) || ("${REF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}\#.*$ ) ]] ; then
        REF_ANCHOR=""
        if [[ "${REF_LINK}" =~ ^(d|p|l|s|q|f){1}[0-9]{2,3}\#.*$ ]] ; then
          REF_ANCHOR="$(echo "${REF_LINK}" | cut -d"#" -f2 || true)"
          REF_LINK="$(echo "${REF_LINK}" | cut -d"#" -f1 || true)"
        fi
        # link modules
        readarray -t MODUL_ARR_LINK < <( find ./modules \( -iname "${REF_LINK}""_*.sh" ! -iname "*pre.sh" ! -iname "*post.sh" \) || true )
        if [[ "${#MODUL_ARR_LINK[@]}" -gt 0 ]] ; then
          MODUL_ARR_LINK_E="$(echo "${MODUL_ARR_LINK[0]}" | tr '[:upper:]' '[:lower:]' || true)"
          if [[ -n "${REF_ANCHOR}" ]] ; then
            HTML_LINK="$(echo "${REFERENCE_MODUL_LINK}" | sed -e "s@LINK@./$(basename "${MODUL_ARR_LINK_E%.sh}").html\#anchor_${REF_ANCHOR}@" || true)"
          else
            HTML_LINK="$(echo "${REFERENCE_MODUL_LINK}" | sed -e "s@LINK@./$(basename "${MODUL_ARR_LINK_E%.sh}").html@" || true)"
          fi
          LINE_NUMBER_INFO_PREV="$(( REF_LINK_NUMBER - 1 ))"
          while [[ "$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${P_START}${SPAN_END}${P_END}" ]] ; do
            LINE_NUMBER_INFO_PREV=$(( LINE_NUMBER_INFO_PREV - 1 ))
          done
          LINK_COMMAND_ARR+=( "${LINE_NUMBER_INFO_PREV}"'s@^@'"${HTML_LINK}"'@' "${LINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
        fi
      elif [[ "${REF_LINK}" =~ ${URL_REGEX} ]] ; then
        LINE_NUMBER_INFO_PREV="$(( REF_LINK_NUMBER - 1 ))"
        while [[ ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${BR}" ) ]] ; do
          LINE_NUMBER_INFO_PREV=$(( LINE_NUMBER_INFO_PREV - 1 ))
        done
        HTML_LINK="$(echo "${REFERENCE_MODUL_EXT_LINK}" | sed -e "s@LINK@${REF_LINK}@")""$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")""${LINK_END}"
        LINK_COMMAND_ARR+=( "${LINE_NUMBER_INFO_PREV}"'s@.*@'"${HTML_LINK}"'@' )
      else
        LINE_NUMBER_INFO_PREV="$(grep -a -n -E "\[REF\] ""${REF_LINK}" "${LINK_FILE}" | cut -d":" -f1 || true)"
      fi
    done
  fi

  if [[ ${IGNORE_LINKS} -eq 0 ]] ; then
    # web links
    if ( grep -a -q -E '(https?|ftp|file):\/\/' "${LINK_FILE}" ) ; then
      readarray -t WEB_LINKS < <( grep -a -n -o -E '(\b(https?|ftp|file):\/\/) ?[-A-Za-z0-9+&@#\/%?=~_|!:,.;]+[-A-Za-z0-9+&@#\/%=~a_|]' "${LINK_FILE}" | uniq || true)
      for WEB_LINK in "${WEB_LINKS[@]}" ; do
        WEB_LINK_LINE_NUM="$(echo "${WEB_LINK}" | cut -d ":" -f 1 || true)"
        WEB_LINK_URL="$(echo "${WEB_LINK}" | cut -d ":" -f 2- || true)"
        WEB_LINK_URL="${WEB_LINK_URL%\\}"
        if [[ -n "${WEB_LINK}" ]] ; then
          HTML_LINK="$(echo "${LINK}" | sed -e "s@LINK@${WEB_LINK_URL}@g")""${WEB_LINK_URL}""${LINK_END}" || true
          LINK_COMMAND_ARR+=( "${WEB_LINK_LINE_NUM}"'s@'"${WEB_LINK_URL}"'@'"${HTML_LINK}"'@' )
        fi
      done
    fi

    # linux exploit suggester links
    if ( grep -a -q -E 'Exploit \(linux-exploit-suggester' "${LINK_FILE}" ) ; then
      readarray -t LES_LINE_ARR < <( grep -a -o -n -E 'Exploit \(linux-exploit-suggester' "${LINK_FILE}" | cut -d":" -f1)
      for LES_LINE in "${LES_LINE_ARR[@]}" ; do
        HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./s25_kernel_check.html@g")""linux-exploit-suggester""${LINK_END}"
        LINK_COMMAND_ARR+=( "${LES_LINE}""s@linux-exploit-suggester@""${HTML_LINK}"'@' )
      done
    fi

    # Add anchors to link inside of modules
    if ( grep -a -q -E '\[ANC\]' "${LINK_FILE}" ) ; then
      readarray -t ANC_ARR < <(grep -a -n -E '\[ANC\].*' "${LINK_FILE}" | cut -d':' -f1 )
      for ANC_NUMBER in "${ANC_ARR[@]}" ; do
        ANC="$(sed "${ANC_NUMBER}""q;d" "${LINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
        ANC_LINE="$(echo "${ANCHOR}" | sed -e "s@ANCHOR@anchor_${ANC}@g" || true)""${LINK_END}"
        LINK_COMMAND_ARR+=( "${ANC_NUMBER}"'s@$@'"${ANC_LINE}"'@' )
      done
    fi

    # Exploit links and additional files
    if ( grep -a -q -E 'EDB ID:' "${LINK_FILE}" ) ; then
      readarray -t EXPLOITS_IDS < <( grep -a -n -o -E ".*EDB ID: ([0-9]*)[\ ]?*.*" "${LINK_FILE}" | uniq || true)
      for EXPLOIT_ID in "${EXPLOITS_IDS[@]}" ; do
        EXPLOIT_ID_LINE="$(echo "${EXPLOIT_ID}" | cut -d ":" -f 1)"
        EXPLOIT_ID_STRING="$(echo "${EXPLOIT_ID}" | cut -d ":" -f 2-)"
        if [[ -n "${EXPLOIT_ID_STRING}" ]] ; then
          EXPLOIT_ID="$(echo "${EXPLOIT_ID_STRING}" | grep -a -o -E "EDB ID: ([0-9]*)" | cut -d ":" -f 2 | sed -e 's/^[[:space:]]*//' || true)"
          EXPLOIT_FILE="${LOG_DIR}""/f20_vul_aggregator/exploit/""${EXPLOIT_ID}"".txt"
          if [[ -f "${EXPLOIT_FILE}" ]] ; then
            # generate exploit file
            generate_info_file "${EXPLOIT_FILE}" "${BACK_LINK}" &
            WAIT_PIDS_WR+=( "$!" )
            HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${BACK_LINK}" | cut -d"." -f1 )/${EXPLOIT_ID}.html@g")""${EXPLOIT_ID}""${LINK_END}"
          else
            HTML_LINK="$(echo "${EXPLOIT_LINK}" | sed -e "s@LINK@${EXPLOIT_ID}@g")""${EXPLOIT_ID}""${LINK_END}"
          fi
          LINK_COMMAND_ARR+=( "${EXPLOIT_ID_LINE}"'s@'"${EXPLOIT_ID}"'@'"${HTML_LINK}"'@' )
        fi
      done
    fi

    # MSF key links and additional files
    if ( grep -a -q -E 'Exploit.*MSF' "${LINK_FILE}" ) ; then
      readarray -t MSF_KEY_F < <( grep -a -n -o -E "MSF: (([0-9a-z_][\ ]?)+)*" "${LINK_FILE}" | uniq || true)
      for MSF_KEY in "${MSF_KEY_F[@]}" ; do
        MSF_KEY_LINE="$(echo "${MSF_KEY}" | cut -d ":" -f 1)"
        MSF_KEY_STRING="$(echo "${MSF_KEY}" | cut -d ":" -f 3- | sed -e 's/^[[:space:]]*//')"
        readarray -t MSF_KEY_STRING_ARR < <(echo "${MSF_KEY_STRING}" | tr " " "\n" | uniq )
        for MSF_KEY_ELEM in "${MSF_KEY_STRING_ARR[@]}" ; do
          MSF_KEY_FILE="${LOG_DIR}""/f20_vul_aggregator/exploit/msf_""${MSF_KEY_ELEM}"".rb"
          if [[ -f "${MSF_KEY_FILE}" ]] ; then
            # copy msf file
            local RES_PATH
            RES_PATH="${ABS_HTML_PATH}""/""$(echo "${BACK_LINK}" | cut -d"." -f1 )""/res"
            if [[ ! -d "${RES_PATH}" ]] ; then mkdir -p "${RES_PATH}" > /dev/null || true; fi
            cp "${MSF_KEY_FILE}" "${RES_PATH}""/""$(basename "${MSF_KEY_FILE}")" || true
            HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./$(echo "${BACK_LINK}" | cut -d"." -f1 )/res/$(basename "${MSF_KEY_FILE}")@g")""${MSF_KEY_ELEM}""${LINK_END}"
            LINK_COMMAND_ARR+=( "${MSF_KEY_LINE}"'s@'"${MSF_KEY_ELEM}"'@'"${HTML_LINK}"'@' )
          fi
        done
      done
    fi

    # Trickest key links to Github
    # Todo: Remove trickest integration
    if ( grep -a -q -E 'Exploit.*Github' "${LINK_FILE}" ) ; then
      readarray -t TRICKEST_KEY_F < <( grep -a -n -o -E "Github: .*" "${LINK_FILE}" | sed 's/ (G)//g' | sed 's/Github: //' | sed 's/).*//' | uniq || true)
      for TRICKEST_KEY in "${TRICKEST_KEY_F[@]}" ; do
        TRICKEST_ID_LINE="$(echo "${TRICKEST_KEY}" | cut -d ":" -f 1)"
        TRICKEST_ID_STRING="$(echo "${TRICKEST_KEY}" | cut -d ":" -f 2-)"
        readarray -t TRICKEST_KEY_STRING_ARR < <(echo "${TRICKEST_ID_STRING}" | tr " " "\n" | uniq)
        for TRICKEST_KEY_ELEM in "${TRICKEST_KEY_STRING_ARR[@]}" ; do
          # we rename / to _ for the display name of the link -> in the cli report it is possible to just copy and paste the URL to github,
          # in the web reporter you can click it
          TRICKEST_KEY_NAME="$(echo "${TRICKEST_KEY_ELEM}" | tr "/" "_")"
          HTML_LINK="$(echo "${GITHUB_LINK}" | sed -e "s@LINKNAME@${TRICKEST_KEY_NAME}@g" | sed -e "s@LINK@${TRICKEST_KEY_ELEM}@g")""${TRICKEST_KEY_NAME}""${LINK_END}"
          LINK_COMMAND_ARR+=( "${TRICKEST_ID_LINE}"'s@'"${TRICKEST_KEY_ELEM}"'@'"${HTML_LINK}"'@' )
        done
      done
    fi

    if ( grep -a -q -E 'Exploit.*Snyk' "${LINK_FILE}" ) ; then
      readarray -t SNYK_KEY_F < <( grep -a -n -o -E "Snyk: .*" "${LINK_FILE}" | sed 's/Snyk: //' | uniq || true)
      for SNYK_KEY in "${SNYK_KEY_F[@]}" ; do
        SNYK_ID_LINE="$(echo "${SNYK_KEY}" | cut -d ":" -f 1)"
        SNYK_ID_STRING="$(echo "${SNYK_KEY}" | cut -d ":" -f 2-)"
        readarray -t SNYK_KEY_STRING_ARR < <(echo "${SNYK_ID_STRING}" | tr " " "\n" | grep "SNYK-" | uniq || true)
        for SNYK_KEY_ELEM in "${SNYK_KEY_STRING_ARR[@]}" ; do
          HTML_LINK="$(echo "${SNYK_LINK}" | sed -e "s@LINKNAME@${SNYK_KEY_ELEM}@g" | sed -e "s@LINK@${SNYK_KEY_ELEM}@g")""${SNYK_KEY_ELEM}""${LINK_END}"
          LINK_COMMAND_ARR+=( "${SNYK_ID_LINE}"'s@'"${SNYK_KEY_ELEM}"'@'"${HTML_LINK}"'@' )
        done
      done
    fi

    if ( grep -a -q -E 'Exploit.*PSS' "${LINK_FILE}" ) ; then
      readarray -t PSS_KEY_F < <( grep -a -n -o -E "PSS: .*" "${LINK_FILE}" | sed 's/PSS: //' | uniq || true)
      for PSS_KEY in "${PSS_KEY_F[@]}" ; do
        PSS_ID_LINE="$(echo "${PSS_KEY}" | cut -d ":" -f 1)"
        PSS_ID_STRING="$(echo "${PSS_KEY}" | cut -d ":" -f 2-)"
        readarray -t PSS_KEY_STRING_ARR < <(echo "${PSS_ID_STRING}" | tr " " "\n" | grep -E "[0-9]+/.*\.html" | uniq || true)
        for PSS_KEY_NAME in "${PSS_KEY_STRING_ARR[@]}" ; do
          # PSS_KEY_NAME="$(echo "${PSS_KEY_ELEM}" | tr "/" "_")"
          HTML_LINK="$(echo "${PSS_LINK}" | sed -e "s@LINKNAME@${PSS_KEY_NAME}@g" | sed -e "s@LINK@${PSS_KEY_NAME}@g")""${PSS_KEY_NAME}""${LINK_END}"
          LINK_COMMAND_ARR+=( "${PSS_ID_LINE}"'s@'"${PSS_KEY_NAME}"'@'"${HTML_LINK}"'@' )
        done
      done
    fi

    # CVE links
    if ( grep -a -q -E '(CVE)' "${LINK_FILE}" ) ; then
      # in l35 html report we do not link CVE - we have Metasploit links in there
      if ! [[ "${LINK_FILE}" == *"l35_"* ]]; then
        readarray -t CVE_IDS < <( grep -a -n -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' "${LINK_FILE}" | uniq || true)
        for CVE_ID in "${CVE_IDS[@]}" ; do
          CVE_ID_LINE="$(echo "${CVE_ID}" | cut -d ":" -f 1)"
          CVE_ID_STRING="$(echo "${CVE_ID}" | cut -d ":" -f 2-)"
          if [[ -n "${CVE_ID_STRING}" ]] ; then
            HTML_LINK="$(echo "${CVE_LINK}" | sed -e "s@LINK@${CVE_ID_STRING}@g")""${CVE_ID_STRING}""${LINK_END}"
            if [[ "${LINK_FILE}" == *"f20_vul_aggregator"* ]]; then
              LINK_COMMAND_ARR+=( "${CVE_ID_LINE}"'s@'"[[:blank:]]${CVE_ID_STRING}"'@'"\t${HTML_LINK}""@" )
            else
              LINK_COMMAND_ARR+=( "${CVE_ID_LINE}"'s@'"${CVE_ID_STRING}"'@'"${HTML_LINK}"'@' )
            fi
          fi
        done
      fi
    fi

    # CWE links
    if ( grep -a -q -E '(CWE)' "${LINK_FILE}" ) ; then
      readarray -t CWE_IDS < <( grep -a -n -E -o 'CWE[0-9]{3,4}' "${LINK_FILE}" | uniq || true)
      for CWE_ID in "${CWE_IDS[@]}" ; do
        CWE_ID_LINE="$(echo "${CWE_ID}" | cut -d ":" -f 1)"
        CWE_ID_STRING="$(echo "${CWE_ID}" | cut -d ":" -f 2-)"
        CWE_ID_NUMBER="${CWE_ID_STRING:3}"
        if [[ -n "${CWE_ID_STRING}" ]] ; then
          HTML_LINK="$(echo "${CWE_LINK}" | sed -e "s@LINK@${CWE_ID_NUMBER}@g")""${CWE_ID_STRING}""${LINK_END}"
          LINK_COMMAND_ARR+=( "${CWE_ID_LINE}"'s@'"${CWE_ID_STRING}"'@'"${HTML_LINK}"'@' )
        fi
      done
    fi

    # License links
    if ( grep -a -q -E 'License: ' "${LINK_FILE}" ) ; then
      LIC_CODE_ARR=()
      LIC_URL_ARR=()
      while read -r LICENSE_LINK_LINE; do
        if echo "${LICENSE_LINK_LINE}" | grep -v -q "^[^#*/;]"; then
          continue
        fi
        LIC_CODE_ARR=( "${LIC_CODE_ARR[@]}" "$(echo "${LICENSE_LINK_LINE}" | cut -d';' -f1)")
        LIC_URL_ARR=( "${LIC_URL_ARR[@]}" "$(echo "${LICENSE_LINK_LINE}" | cut -d';' -f2-)")
      done  < "${CONFIG_DIR}"/bin_version_strings_links.cfg

      readarray -t LICENSE_LINES < <( grep -a -n -E -o 'License: .*$' "${LINK_FILE}" | uniq)
      for LICENSE_LINE in "${LICENSE_LINES[@]}" ; do
        LICENSE_LINE_NUM="$(echo "${LICENSE_LINE}" | cut -d: -f1)"
        LICENSE_STRING="$(echo "${LICENSE_LINE}" | cut -d: -f3 | sed -e 's/<[^>]*>//g' )"
        LIC_URL=""
        for I in "${!LIC_CODE_ARR[@]}" ; do
          if [[ "${LIC_CODE_ARR[${I}]}" == "${LICENSE_STRING:1}" ]] ; then
            LIC_URL="${LIC_URL_ARR[${I}]}"
          fi
        done
        if [[ -n "${LIC_URL}" ]] ; then
          HTML_LINK="$(echo "${LICENSE_LINK}" | sed -e "s@LINK@${LIC_URL}@g")""${LICENSE_STRING:1}""${LINK_END}"
          LINK_COMMAND_ARR+=( "${LICENSE_LINE_NUM}"'s@'"${LICENSE_STRING:1}"'@'"${HTML_LINK}"'@' )
        fi
      done
    fi

    # Arachni report
    if [[ "${LINK_FILE}" == *"l25_web_checks"* ]]; then
      if [[ -d "${LOG_DIR}/l25_web_checks/arachni_report/" ]]; then
        print_output "[*] Arachni report found ... copy it to ${ABS_HTML_PATH}/l25_web_checks" "no_log"
        # copy arachni report to report directory
        if ! [[ -d "${ABS_HTML_PATH}/l25_web_checks" ]]; then
          mkdir "${ABS_HTML_PATH}/l25_web_checks"
        fi
        cp -r "${LOG_DIR}/l25_web_checks/arachni_report/" "${ABS_HTML_PATH}/l25_web_checks/"
        # generate a html link
        if [[ -f "${LINK_FILE}" ]]; then
          print_output "[*] Generating Arachni linking ${LINK_FILE}" "no_log"
          LINK_COMMAND_ARR+=( 's@'"Arachni report created"'@'"${ARACHNI_LINK}""Arachni web application report""${LINK_END}"'@' )
        fi
      fi
    fi

    # [LOV] anchor for JS popup messages
    if ( grep -a -q -E '\[LOV\]' "${LINK_FILE}" ) ; then
      readarray -t LOV_LINKS_L_NUMBER < <(grep -a -n -E '\[LOV\].*' "${LINK_FILE}" | cut -d':' -f1 )
      for LOV_LINK_NUMBER in "${LOV_LINKS_L_NUMBER[@]}" ; do
        DEPTH="."
        LOV_LINK="$(sed "${LOV_LINK_NUMBER}""q;d" "${LINK_FILE}" | cut -c12- | cut -d'<' -f1 || true)"
        if [[ -f "$(echo "${LOV_LINK}" | cut -d"#" -f1)" ]] ; then
          echo "LOV_LINK: ${LOV_LINK}"
          LINE_NUMBER_INFO_PREV="$(( LOV_LINK_NUMBER - 1 ))"
          while [[ ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${P_START}${SPAN_END}${P_END}") || ("$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}")" == "${BR}" ) ]] ; do
            LINE_NUMBER_INFO_PREV=$(( LINE_NUMBER_INFO_PREV - 1 ))
            echo "X LINE_NUMBER_INFO_PREV: ${LINE_NUMBER_INFO_PREV}"
          done
          LOV_LINE_BEFORE="$(sed "${LINE_NUMBER_INFO_PREV}""q;d" "${LINK_FILE}" || true)"
          # HTML_LINK="$(echo "${LOV_LINK}" | sed -e "s@LINK@${DEPTH}/$(echo "${BACK_LINK}" | cut -d"." -f1)/$(basename "${LOV_LINK%."${LOV_LINK##*.}"}").html@g" || true)"
          HTML_LINK="$(echo "${LOCAL_OVERLAY_LINK}" | sed -e "s@LINK@${LOV_LINK}@g" || true)"
          echo "HTML_LINK: ${HTML_LINK}"
          echo "LOV_LINE_BEFORE: ${LOV_LINE_BEFORE}"
          echo "LINE_NUMBER_INFO_PREV: ${LINE_NUMBER_INFO_PREV}"
          LINK_COMMAND_ARR+=( "${LINE_NUMBER_INFO_PREV}"'s@^@'"${HTML_LINK}"'@' "${LINE_NUMBER_INFO_PREV}"'s@$@'"${LINK_END}"'@')
          echo "LINK_COMMAND_ARR: ${LINK_COMMAND_ARR[*]}"
        fi
      done
    fi
  fi

  if [[ "${#LINK_COMMAND_ARR[@]}" -gt 0 ]] ; then
    if [[ -f "${LINK_FILE}" ]]; then
      local INSERT_ARR=()
      local LOCAL_ARR=()
      local INSERT_SIZE=100
      disable_strict_mode "${STRICT_MODE}" 0
      for (( X=0; X<${#LINK_COMMAND_ARR[@]}; X++ )) ; do
        LOCAL_ARR+=("${LINK_COMMAND_ARR[${X}]}")
        INSERT_ARR+=('-e' "${LINK_COMMAND_ARR[${X}]}")
        if [[ ( ( $((X%INSERT_SIZE)) -eq 0 ) && ${X} -ne 0 ) || ( $((${#LINK_COMMAND_ARR[@]}-1)) -eq ${X} ) ]] ; then
          SED_ERROR="$(sed -i "${INSERT_ARR[@]}" "${LINK_FILE}" 2>&1 >/dev/null)"
          if [[ -n "${SED_ERROR}" ]] ; then
            printf "ERROR:\nInsertion of Chunk failed:\n%s\n\nError message:\n%s\n" "${INSERT_ARR[@]}" "${SED_ERROR}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${LINK_FILE}").txt"
            SED_ERROR=""
            printf "SINGLE_INSERTION:\n" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${LINK_FILE}").txt"
            for LINE in "${LOCAL_ARR[@]}" ; do
              printf "%s\n" "${LINE}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${LINK_FILE}").txt"
              SED_ERROR=$(sed -i "${LINE}" "${LINK_FILE}" 2>&1 >/dev/null)
              if [[ -n "${SED_ERROR}" ]] ; then
                printf "ERROR:\nInsertion of single link failed:\n%s\n" "${SED_ERROR}" >> "${ABS_HTML_PATH}${ERR_PATH}/web_report_error_$(basename "${LINK_FILE}").txt"
              fi
            done
          fi
          INSERT_ARR=()
          LOCAL_ARR=()
          SED_ERROR=""
        fi
      done
      enable_strict_mode "${STRICT_MODE}" 0
    fi
  fi

  wait_for_pid "${WAIT_PIDS_WR[@]}"
  if [[ -f "${LINK_FILE}" ]]; then
    sed -i -E 's@^<pre>((\[REF\])|(\[ANC\])).*</pre>@@g' "${LINK_FILE}" || true
  fi
}

strip_color_tags()
{
  echo "${1:-}" | sed 's@\x1b\[[0-9;]*m@@g' | tr -d '\000-\010\013\014\016-\037'
}

# often we have additional information, like exploits or cve's
generate_info_file()
{
  INFO_FILE=${1:-}
  SRC_FILE=${2:-}
  CUSTOM_SUB_PATH=${3:-}

  local DEPTH_HTML_HEADER="./.."

  INFO_HTML_FILE="$(basename "${INFO_FILE%."${INFO_FILE##*.}"}"".html")"

  # extract just the log directory name of the module:
  LOG_DIR_MODULE="$(echo "${LOG_PATH_MODULE}" | sed -e "s#""${LOG_DIR}""##g")"
  LOG_DIR_MODULE="${LOG_DIR_MODULE//\/}"
  SRC_FILE_NAME="$(echo "${SRC_FILE}" | cut -d"." -f1 )"

  if [[ -z "${CUSTOM_SUB_PATH}" ]] ; then
    if [[ "${LOG_DIR_MODULE}" !=  "${SRC_FILE_NAME}" ]]; then
      INFO_PATH="${ABS_HTML_PATH}""/${LOG_DIR_MODULE}/""${SRC_FILE_NAME}"
      # INFO: now we have another directory depth and we need to adjust the html header
      DEPTH_HTML_HEADER="./../.."
    else
      INFO_PATH="${ABS_HTML_PATH}""/${LOG_DIR_MODULE}"
      DEPTH_HTML_HEADER="./.."
    fi
  else
    INFO_PATH="${ABS_HTML_PATH}""/${LOG_DIR_MODULE}/""${CUSTOM_SUB_PATH}"
  fi

  local RES_PATH
  RES_PATH="${INFO_PATH}""/res"

  if ! [[ -d "${INFO_PATH}" ]]; then
    mkdir -p "${INFO_PATH}" || true
  fi

  if [[ ! -f "${INFO_PATH}""/""${INFO_HTML_FILE}" ]] && [[ -f "${INFO_FILE}" ]] ; then
    cp "./helpers/base.html" "${INFO_PATH}""/""${INFO_HTML_FILE}" || true
    sed -i -e "s:\.\/:""${DEPTH_HTML_HEADER}""/:g" "${INFO_PATH}""/""${INFO_HTML_FILE}"

    SUB_PATH="$(dirname "$(echo "${INFO_FILE}" | sed -e "s#""${LOG_DIR}""##g")")"
    TMP_INFO_FILE="${ABS_HTML_PATH}""${TEMP_PATH}""/""${SUB_PATH}""/""${INFO_HTML_FILE}"
    TMP_INFO_DIR="${ABS_HTML_PATH}""${TEMP_PATH}""/""${SUB_PATH}"

    # add back Link anchor to navigation
    if [[ -n "${SRC_FILE}" ]] ; then
      LINE_NUMBER_INFO_NAV=$(grep -a -n "navigation start" "${INFO_PATH}""/""${INFO_HTML_FILE}" | cut -d":" -f1 || true)
      NAV_INFO_BACK_LINK="$(echo "${MODUL_LINK}" | sed -e "s@LINK@./../${SRC_FILE}@g")"
      sed -i "${LINE_NUMBER_INFO_NAV}""i""${NAV_INFO_BACK_LINK}""&laquo; Back to ""$(basename "${SRC_FILE%.html}")""${LINK_END}" "${INFO_PATH}""/""${INFO_HTML_FILE}"
    fi

    ! [[ -d "${TMP_INFO_DIR}" ]] && mkdir -p "${TMP_INFO_DIR}"
    cp "${INFO_FILE}" "${TMP_INFO_FILE}" 2>/dev/null || true

    sed -i -e 's@&@\&amp;@g ; s/@/\&commat;/g ; s@<@\&lt;@g ; s@>@\&gt;@g' "${TMP_INFO_FILE}" || true
    sed -i '\@\[\*\]\ Statistics@d' "${TMP_INFO_FILE}" || true

    sed -i -e "s:^:${P_START}: ; s:$:${P_END}:" "${TMP_INFO_FILE}" || true
    # add html tags for style
    add_color_tags "${TMP_INFO_FILE}"
    sed -i -e "s:[=]{65}:${HR_DOUBLE}:g ; s:^[-]{65}$:${HR_MONO}:g" "${TMP_INFO_FILE}" || true

    # add link tags to links/generate info files and link to them and write line to tmp file
    add_link_tags "${TMP_INFO_FILE}" "${INFO_HTML_FILE}"

    readarray -t EXPLOITS_IDS_INFO < <( grep -a 'Exploit DB Id:' "${INFO_FILE}" | sed -e 's@[^0-9\ ]@@g ; s@\ @@g' | sort -u || true)
    for EXPLOIT_ID_INFO in "${EXPLOITS_IDS_INFO[@]}" ; do
      ONLINE="$(echo "${EXPLOIT_LINK}" | sed -e "s@LINK@${EXPLOIT_ID_INFO}@g" || true)""${EXPLOIT_ID_INFO}""${LINK_END}"
      printf "%s%sOnline: %s%s\n" "${HR_MONO}" "${P_START}" "${ONLINE}" "${P_END}" >> "${TMP_INFO_FILE}"
    done

    readarray -t EXPLOIT_FILES < <(grep -a "File: " "${INFO_FILE}" | cut -d ":" -f 2 | sed 's@^\ @@' | sort -u || true)
    for E_PATH in "${EXPLOIT_FILES[@]}" ; do
      if [[ -f "${E_PATH}" ]] ; then
        if [[ ! -d "${RES_PATH}" ]] ; then mkdir "${RES_PATH}" > /dev/null || true ; fi
        cp "${E_PATH}" "${RES_PATH}""/""$(basename "${E_PATH}")" || true
        E_HTML_LINK="$(echo "${LOCAL_LINK}" | sed -e "s@LINK@./res/$(basename "${E_PATH}")@g")""$(basename "${E_PATH}")""${LINK_END}"
        printf "%s%sFile: %s%s\n" "${HR_MONO}" "${P_START}" "${E_HTML_LINK}" "${P_END}" >> "${TMP_INFO_FILE}"
      fi
    done

    # add content of temporary html into template
    sed -i "/content start/ r ${TMP_INFO_FILE}" "${INFO_PATH}""/""${INFO_HTML_FILE}"
  fi
}

generate_report_file()
{
  REPORT_FILE=${1:-}
  # if set to 1, then generate file in supplementary folder and link to menu
  SUPPL_FILE_GEN=${2:-}

  if ! ( grep -a -o -i -q "$(basename "${REPORT_FILE%."${REPORT_FILE##*.}"}")"" nothing reported" "${REPORT_FILE}" ) ; then
    HTML_FILE="$(basename "${REPORT_FILE%."${REPORT_FILE##*.}"}"".html" 2>/dev/null || true)"
    if [[ ${SUPPL_FILE_GEN} -eq 1 ]] ; then
      cp "./helpers/base.html" "${ABS_HTML_PATH}${SUPPL_PATH_HTML}""/""${HTML_FILE}" || true
    else
      cp "./helpers/base.html" "${ABS_HTML_PATH}""/""${HTML_FILE}" || true
    fi
    TMP_FILE="${ABS_HTML_PATH}""${TEMP_PATH}""/""${HTML_FILE}"
    MODUL_NAME=""

    # parse log content and add to html file
    LINE_NUMBER_REP_NAV=$(grep -a -n "navigation start" "${ABS_HTML_PATH}""/""${HTML_FILE}" | cut -d":" -f1)

    cp "${REPORT_FILE}" "${TMP_FILE}" || true
    sed -i -e 's@&@\&amp;@g ; s/@/\&commat;/g ; s@<@\&lt;@g ; s@>@\&gt;@g' "${TMP_FILE}"
    sed -i '\@\[\*\]\ Statistics@d' "${TMP_FILE}"

    # module title anchor links
    if ( grep -a -q -E '[=]{65}' "${TMP_FILE}" ) ; then
      MODUL_NAME="$( strip_color_tags "$(grep -a -E -B 1 '[=]{65}' "${TMP_FILE}" | head -n 1 )" | cut -d" " -f2- )"
      if [[ -n "${MODUL_NAME}" ]] ; then
        # add anchor to file
        A_MODUL_NAME="$(echo "${MODUL_NAME}" | sed -e "s@\ @_@g" | tr "[:upper:]" "[:lower:]")"
        LINE="$(echo "${TITLE_ANCHOR}" | sed -e "s@ANCHOR@${A_MODUL_NAME}@g")""${MODUL_NAME}""${LINK_END}"
        sed -i -E "s@${MODUL_NAME}@${LINE}@" "${TMP_FILE}"
        # add link to index navigation
        add_link_to_index "${HTML_FILE}" "${MODUL_NAME}"
        # add module anchor to navigation
        NAV_LINK="$(echo "${MODUL_LINK}" | sed -e "s@LINK@#${A_MODUL_NAME}@g")"
        sed -i "${LINE_NUMBER_REP_NAV}"'s@$@'"${NAV_LINK}""${MODUL_NAME}""${LINK_END}"'@' "${ABS_HTML_PATH}""/""${HTML_FILE}"
      fi
    fi

    # submodule title anchor links
    if ( grep -a -q -E '^[-]{65}$' "${TMP_FILE}" ) ; then
      readarray -t SUBMODUL_NAMES < <( grep -a -E -B 1 '^[-]{65}$' "${TMP_FILE}" | sed -E '\@[-]{65}@d' | grep -a -v "^--")
      for SUBMODUL_NAME in "${SUBMODUL_NAMES[@]}" ; do
        if [[ -n "${SUBMODUL_NAME}" ]] ; then
          SUBMODUL_NAME="$( strip_color_tags "${SUBMODUL_NAME}" | cut -d" " -f 2- )"
          A_SUBMODUL_NAME="$(echo "${SUBMODUL_NAME}" | sed -e "s@[^a-zA-Z0-9]@@g" | tr "[:upper:]" "[:lower:]")"
          LINE="$(echo "${TITLE_ANCHOR}" | sed -e "s@ANCHOR@${A_SUBMODUL_NAME}@g")""${SUBMODUL_NAME}""${LINK_END}"
          sed -i -E "s@${SUBMODUL_NAME}@${LINE}@" "${TMP_FILE}"
          # Add anchor to file
          SUB_NAV_LINK="$(echo "${SUBMODUL_LINK}" | sed -e "s@LINK@#${A_SUBMODUL_NAME}@g")"
          sed -i "${LINE_NUMBER_REP_NAV}"'s@$@'"${SUB_NAV_LINK}""${SUBMODUL_NAME}""${LINK_END}"'@' "${ABS_HTML_PATH}""/""${HTML_FILE}"
        fi
      done
    fi

    sed -i -E -e "s:[=]{65}:${HR_DOUBLE}:g ; s:^[-]{65}$:${HR_MONO}:g" "${TMP_FILE}" || true
    sed -i -e "s:^:${P_START}: ; s:$:${P_END}:" "${TMP_FILE}" || true
    # this fixes the </pre> lines instead of <pre></pre> - something weird with \r\n
    sed -i -E "s:\r${P_END}:${P_END}:" "${TMP_FILE}" || true

    # add html tags for style
    add_color_tags "${TMP_FILE}"

    # add link tags to links/generate info files and link to them and write line to tmp file
    # also parsing for [REF] anchor and generate linked files and link it
    # to ignore all links except [REF], just add '1' as third parameter
    if [[ "$(basename "${REPORT_FILE}" | cut -d "_" -f 1 )" == "s99" ]] ; then
      add_link_tags "${TMP_FILE}" "${HTML_FILE}" 1
    else
      add_link_tags "${TMP_FILE}" "${HTML_FILE}"
    fi

    # add content of temporary html into template
    if [[ ${SUPPL_FILE_GEN} -eq 1 ]] ; then
      sed -i "/content start/ r ${TMP_FILE}" "${ABS_HTML_PATH}${SUPPL_PATH_HTML}""/""${HTML_FILE}"
    else
      sed -i "/content start/ r ${TMP_FILE}" "${ABS_HTML_PATH}""/""${HTML_FILE}"
    fi
    # add aggregator lines to index page
    if [[ "${HTML_FILE}" == "f50"* ]] ; then
      sed -i "/content start/ r ${TMP_FILE}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
    fi
  fi
}

add_link_to_index() {

  insert_line() {
    SEARCH_VAL="${1:-}"
    MODUL_NAME="${2:-}"
    LINE_NUMBER_NAV_INSERT=$(grep -a -m 1 -n "${SEARCH_VAL}" "${ABS_HTML_PATH}""/""${INDEX_FILE}" | cut -d ":" -f 1)
    REP_NAV_LINK="$(echo "${MODUL_INDEX_LINK}" | sed -e "s@LINK@.\/${HTML_FILE}@g" | sed -e "s@CLASS@${CLASS}@g" | sed -e "s@DATA@${DATA}@g")"
    sed -i "${LINE_NUMBER_NAV_INSERT}""i""${REP_NAV_LINK}""${MODUL_NAME}""${LINK_END}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  }
  INDEX_NAV_GROUP_ARR=()
  INDEX_NAV_ARR=()

  HTML_FILE="${1:-}"
  MODUL_NAME="${2:-}"
  DATA="$( echo "${HTML_FILE}" | cut -d "_" -f 1)"
  CLASS="${DATA:0:1}"
  C_NUMBER="$(echo "${DATA:1}" | sed -E 's@^0*@@g')"

  readarray -t INDEX_NAV_ARR < <(sed -n -e '/navigation start/,/navigation end/p' "${ABS_HTML_PATH}""/""${INDEX_FILE}" | sed -e '1d;$d' | grep -a -P -o '(?<=data=\").*?(?=\")' || true)
  readarray -t INDEX_NAV_GROUP_ARR < <(printf -- '%s\n' "${INDEX_NAV_ARR[@]}" | grep -a "${CLASS}" || true)

  if [[ ${#INDEX_NAV_GROUP_ARR[@]} -eq 0 ]] ; then
    # due the design of EMBA, which are already groups the modules (even threaded), it isn't necessary to check -
    # insert new entry at bottom of the navigation
    insert_line "navigation end" "${MODUL_NAME}"
  else
    for (( COUNT=0; COUNT<=${#INDEX_NAV_GROUP_ARR[@]}; COUNT++ )) ; do
      if [[ ${COUNT} -eq 0 ]] && [[ ${C_NUMBER} -lt $( echo "${INDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
        insert_line "${INDEX_NAV_GROUP_ARR[${COUNT}]}" "${MODUL_NAME}"
        continue
      elif [[ ${COUNT} -eq $(( ${#INDEX_NAV_GROUP_ARR[@]}-1 )) ]] && [[ ${C_NUMBER} -gt $( echo "${INDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
        insert_line "navigation end" "${MODUL_NAME}"
        continue
      fi
      # COUNT+1 is not available on the last element - we need to check the array for this:
      if [[ -v INDEX_NAV_GROUP_ARR[${COUNT}] ]] && [[ -v INDEX_NAV_GROUP_ARR[$((COUNT+1))] ]]; then
        if [[ ${C_NUMBER} -gt $( echo "${INDEX_NAV_GROUP_ARR[${COUNT}]:1}" | sed -E 's@^0*@@g' || true) ]] && [[ ${C_NUMBER} -lt $( echo "${INDEX_NAV_GROUP_ARR[$((COUNT+1))]:1}" | sed -E 's@^0*@@g' || true) ]] ; then
          insert_line "${INDEX_NAV_GROUP_ARR[$((COUNT+1))]}" "${MODUL_NAME}"
        fi
      fi
    done
  fi
}

update_index()
{
  # add emba.log to webreport
  generate_report_file "${MAIN_LOG}"
  sed -i -e "s@buttonTimeInvisible@buttonTime@ ; s@TIMELINK@.\/$(basename "${MAIN_LOG%."${MAIN_LOG##*.}"}"".html")@" "${ABS_HTML_PATH}""/""${INDEX_FILE}"

  # generate files in $SUPPL_PATH (supplementary files from modules)
  readarray -t SUPPL_FILES < <(find "${SUPPL_PATH}" ! -path "${SUPPL_PATH}")
  if [[ "${#SUPPL_FILES[@]}" -gt 0 ]] ; then
    sed -i 's@expand_njs hidden@expand_njs@g' "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  fi
  for S_FILE in "${SUPPL_FILES[@]}" ; do
    generate_info_file "${S_FILE}" "" "${SUPPL_PATH_HTML}"
    LINE_NUMBER_NAV=$(grep -a -n "etc start" "${ABS_HTML_PATH}""/""${INDEX_FILE}" | cut -d ":" -f 1)
    REP_NAV_LINK="$(echo "${ETC_INDEX_LINK}" | sed -e "s@LINK@./${SUPPL_PATH_HTML}/$(basename "${S_FILE%."${S_FILE##*.}"}"".html")@g")"
    sed -i "${LINE_NUMBER_NAV}""i""${REP_NAV_LINK}""$(basename "${S_FILE%."${S_FILE##*.}"}")""${LINK_END}" "${ABS_HTML_PATH}""/""${INDEX_FILE}"
  done
  scan_report
  add_arrows

  # remove tempory files from web report
  rm -R "${ABS_HTML_PATH}${TEMP_PATH}"
  rmdir "${ABS_HTML_PATH}${ERR_PATH}" 2>/dev/null || true
  rm -R "${ABS_HTML_PATH}"/qemu_init* 2>/dev/null || true
}

scan_report()
{
  # at the end of an EMBA run, we have to disable all non-valid links to modules
  local LINK_ARR
  readarray -t LINK_ARR < <(grep -a -r -E "class\=\"refmodul\" href=\"(.*)" "${ABS_HTML_PATH}" | cut -d"\"" -f 4 | cut -d"#" -f 1 | sort -u || true)
  local LINK_FILE_ARR
  readarray -t LINK_FILE_ARR < <(grep -a -r -E -l "class\=\"refmodul\" href=\"(.*)" "${ABS_HTML_PATH}" || true)
  for LINK in "${LINK_ARR[@]}" ; do
    for FILE in "${LINK_FILE_ARR[@]}" ; do
      if ! [[ -f "${ABS_HTML_PATH}""/""${LINK}" ]] ; then
        sed -i "s@class=\"refmodul\" href=\"(${LINK})\"@@g" "${FILE}"
      fi
    done
  done
}

add_arrows()
{
  local D_MODULE_ARR
  readarray -t D_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./d[0-9]*.*" | sort -V || true)
  local P_MODULE_ARR
  readarray -t P_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./p[0-9]*.*" | sort -V || true)
  local S_MODULE_ARR
  readarray -t S_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./s[0-9]*.*" | sort -V || true)
  local L_MODULE_ARR
  readarray -t L_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./l[0-9]*.*" | sort -V || true)
  local F_MODULE_ARR
  readarray -t F_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./f[0-9]*.*" | sort -V || true)
  local Q_MODULE_ARR
  readarray -t Q_MODULE_ARR < <(find "${ABS_HTML_PATH}" -maxdepth 1 -name "*.html" | grep -a -E "./q[0-9]*.*" | sort -V || true)
  local ALL_MODULE_ARR
  ALL_MODULE_ARR=( "${ABS_HTML_PATH}""/""${INDEX_FILE}" "${D_MODULE_ARR[@]}" "${P_MODULE_ARR[@]}" "${S_MODULE_ARR[@]}" "${Q_MODULE_ARR[@]}" "${L_MODULE_ARR[@]}" "${F_MODULE_ARR[@]}")
  for M_NUM in "${!ALL_MODULE_ARR[@]}"; do
    if [[ "${M_NUM}" -gt 0 ]] ; then
      FIRST_LINK="${ALL_MODULE_ARR[$(( M_NUM - 1 ))]}"
      LINE_NUMBER_A_BUTTON=$(grep -a -m 1 -n "buttonForward" "${ALL_MODULE_ARR[${M_NUM}]}" | cut -d ":" -f 1 || true)
      HTML_LINK="$(echo "${ARROW_LINK}" | sed -e "s@LINK@./""$(basename "${FIRST_LINK}")""@g")"
      sed -i -e "${LINE_NUMBER_A_BUTTON}"'s@^@'"${HTML_LINK}"'@' -e "${LINE_NUMBER_A_BUTTON}"'s@$@'"${LINK_END}"'@' -e "${LINE_NUMBER_A_BUTTON}""s@nonClickable @@" -e "${LINE_NUMBER_A_BUTTON}""s@stroke=\"#444\"@stroke=\"#fff\"@" "${ALL_MODULE_ARR[${M_NUM}]}" || true
    fi
    if [[ "$(( M_NUM + 1 ))" -lt "${#ALL_MODULE_ARR[@]}" ]] ; then
      SECOND_LINK="${ALL_MODULE_ARR[$(( M_NUM + 1 ))]}"
      LINE_NUMBER_A_BUTTON=$(grep -a -m 1 -n "buttonBack" "${ALL_MODULE_ARR[${M_NUM}]}" | cut -d ":" -f 1 || true)
      HTML_LINK="$(echo "${ARROW_LINK}" | sed -e "s@LINK@./""$(basename "${SECOND_LINK}")""@g")"
      sed -i -e "${LINE_NUMBER_A_BUTTON}"'s@^@'"${HTML_LINK}"'@' -e "${LINE_NUMBER_A_BUTTON}"'s@$@'"${LINK_END}"'@' -e "${LINE_NUMBER_A_BUTTON}""s@nonClickable @@" -e "${LINE_NUMBER_A_BUTTON}""s@stroke=\"#444\"@stroke=\"#fff\"@" "${ALL_MODULE_ARR[${M_NUM}]}" || true
    fi
  done
}

prepare_report()
{
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
