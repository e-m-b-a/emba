#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner
# Contributor(s): Benedikt Kuehne

# Description: Identifies the main Linux distribution like Kali Linux, Debian, Fedora or OpenWRT

S06_distribution_identification()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "System identification"
  pre_module_reporter "${FUNCNAME[0]}"

  export DLINK_FW_VER=""
  local lOUTPUT=0
  local lPATTERN=""
  local lIDENTIFIER=""
  local OUT1=""
  local SED_COMMAND=""
  local FILE_QUOTED=""
  local CONFIG=""
  local lFILE=""
  local lSEARCH_FILE=""
  local lFOUND_FILES_ARR=()
  local lFILENAME=""
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lCPE_IDENTIFIER="NA"
  local lPURL_IDENTIFIER="NA"
  local lCSV_RULE=""
  local lPACKAGING_SYSTEM="static_distri_analysis"
  local lOS_IDENTIFIED=""

  write_csv_log "file" "type" "identifier" "csv_rule"

  while read -r CONFIG; do
    if safe_echo "${CONFIG}" | grep -q "^[^#*/;]"; then
      lSEARCH_FILE="$(safe_echo "${CONFIG}" | cut -d\; -f2)"
      # echo "lSEARCH_FILE: $lSEARCH_FILE"
      # echo "FIRMWARE_PATH: $FIRMWARE_PATH"
      if [[ "${lSEARCH_FILE}" == *"os-release"* ]] || [[ "${lSEARCH_FILE}" == *"lsb-release"* ]]; then
        # lets check if we have already a valid debian entry -> if so, we can skip this test
        # this usually happens if we have already found an os_release or lsb-release file
        # echo "Check for debian - os_release / lsb-release"
        if grep -qE "debian_linux:[0-9]+" "${S06_CSV_LOG}"; then
          print_output "[*] Already identified Debian Linux version -> skipping further tests now" "no_log"
          continue
        fi
      fi
      mapfile -t lFOUND_FILES_ARR < <(find "${FIRMWARE_PATH}" -xdev -iwholename "*${lSEARCH_FILE}" || true)
      for lFILE in "${lFOUND_FILES_ARR[@]}"; do
        # print_output "lFILE: ${lFILE}"
        if [[ -f "${lFILE}" ]]; then
          lPATTERN="$(safe_echo "${CONFIG}" | cut -d\; -f3)"
          # do not use safe_echo for SED_COMMAND
          SED_COMMAND="$(echo "${CONFIG}" | cut -d\; -f4)"
          FILE_QUOTED=$(escape_echo "${lFILE}")
          OUT1="$(eval "${lPATTERN}" "${FILE_QUOTED}" || true)"
          # print_output "lPATTERN: ${lPATTERN}"
          # print_output "SED command: ${SED_COMMAND}"
          # print_output "FILE: ${FILE_QUOTED}"
          # print_output "identified before: ${OUT1}"
          OUT1=$(echo "${OUT1}" | sort -u | tr '\n' ' ')
          OUT1=$(echo "${OUT1}" | tr -d '"')
          # print_output "identified mod: ${OUT1}"
          if [[ -n "${SED_COMMAND}" ]]; then
            lIDENTIFIER=$(echo "${OUT1}" | eval "${SED_COMMAND}" | sed 's/  \+/ /g' | sed 's/ $//' || true)
          else
            lIDENTIFIER=$(echo "${OUT1}" | sed 's/  \+/ /g' | sed 's/ $//' || true)
          fi
          # print_output "[*] lIDENTIFIER: ${lIDENTIFIER}"
          lFILENAME=$(basename "${lFILE,,}")

          if [[ $(basename "${lFILE}") == "image_sign" ]]; then
            # dlink image_sign file handling
            lIDENTIFIER=$(dlink_image_sign "${lIDENTIFIER}")
          fi

          lMD5_CHECKSUM="$(md5sum "${lFILE}" | awk '{print $1}')"
          lSHA256_CHECKSUM="$(sha256sum "${lFILE}" | awk '{print $1}')"
          lSHA512_CHECKSUM="$(sha512sum "${lFILE}" | awk '{print $1}')"

          check_for_s08_csv_log "${S08_CSV_LOG}"

          # spcial case - bmc identifier
          if [[ "${lIDENTIFIER}" != *[0-9]* ]] && [[ "${lIDENTIFIER}" == *"supermicro:bmc"* ]]; then
            print_output "[+] Version information found ${ORANGE}${lIDENTIFIER}${GREEN} in file ${ORANGE}$(print_path "${lFILE}")${GREEN} with Linux distribution detection"
            lCSV_RULE=$(get_csv_rule_distri "${lIDENTIFIER}")
            write_csv_log "${lFILE}" "Linux" "${lIDENTIFIER}" "${lCSV_RULE}"
            lCPE_IDENTIFIER="cpe:${CPE_VERSION}${lCSV_RULE}:*:*:*:*:*:*"
            lOS_IDENTIFIED=$(distri_check)
            lPURL_IDENTIFIER=$(build_generic_purl "${lCSV_RULE}" "${lOS_IDENTIFIED}" "${lBIN_ARCH:-NA}")
            write_log "${lPACKAGING_SYSTEM};${lFILE:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lFILENAME};${lIDENTIFIER:-NA};${lCSV_RULE:-NA};${LIC:-NA};maintainer unknown;NA;${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};Linux distribution identification module" "${S08_CSV_LOG}"
          fi

          # check if not zero and not only spaces
          if [[ -n "${lIDENTIFIER// }" ]] && [[ "${lIDENTIFIER}" == *[0-9]* ]]; then
            if [[ -n "${DLINK_FW_VER}" ]]; then
              print_output "[+] Version information found ${ORANGE}${lIDENTIFIER}${GREEN} in file ${ORANGE}$(print_path "${lFILE}")${GREEN} for D-Link device."
              lCSV_RULE=$(get_csv_rule_distri "${lIDENTIFIER}")
              write_csv_log "${lFILE}" "dlink" "${lIDENTIFIER}" "${lCSV_RULE}"
            else
              print_output "[+] Version information found ${ORANGE}${lIDENTIFIER}${GREEN} in file ${ORANGE}$(print_path "${lFILE}")${GREEN} with Linux distribution detection"
              lCSV_RULE=$(get_csv_rule_distri "${lIDENTIFIER}")
              # print_output "[*] lCSV_RULE: ${lCSV_RULE}"
              write_csv_log "${lFILE}" "Linux" "${lIDENTIFIER}" "${lCSV_RULE}"
            fi
            # lCSV_RULE has 5 fields and looks like the following: :dlink:device:version:*
            lCPE_IDENTIFIER="cpe:${CPE_VERSION}${lCSV_RULE}:*:*:*:*:*:*"
            lOS_IDENTIFIED=$(distri_check)
            local lAPP_TYPE="operating-system"
            local lAPP_LIC=""
            local lAPP_MAINT=""
            lAPP_MAINT=$(echo "${lCSV_RULE}" | cut -d ':' -f2)
            local lAPP_NAME=""
            lAPP_NAME=$(echo "${lCSV_RULE}" | cut -d ':' -f3)
            local lAPP_VERS=""
            lAPP_VERS=$(echo "${lCSV_RULE}" | cut -d ':' -f4-5)
            # it could be that we have a version like 2.14b:* -> we remove the last field
            lAPP_VERS="${lAPP_VERS/:\*}"
            # we use the already (p99) identified architecture for the distri
            local lAPP_ARCH="${ARCH:-NA}"
            lPURL_IDENTIFIER=$(build_generic_purl "${lCSV_RULE}" "${lOS_IDENTIFIED}" "${lAPP_ARCH:-NA}")

            ### new SBOM json testgenerator
            if command -v jo >/dev/null; then
              # add source file path information to our properties array:
              local lPROP_ARRAY_INIT_ARR=()
              lPROP_ARRAY_INIT_ARR+=( "source_path:${lFILE}" )
              if [[ "${lAPP_ARCH}" != "NA" ]]; then
                lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
              fi
              lPROP_ARRAY_INIT_ARR+=( "identifer_detected:${lIDENTIFIER}" )
              lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lCSV_RULE}" )

              build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

              # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
              # final array with all hash values
              if ! build_sbom_json_hashes_arr "${lFILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
                print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
                continue
              fi

              # create component entry - this allows adding entries very flexible:
              build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
            fi

            write_log "${lPACKAGING_SYSTEM};${lFILE:-NA};${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA};${lFILENAME};${lIDENTIFIER:-NA};${lCSV_RULE:-NA};${lAPP_LIC:-NA};maintainer unknown;NA;${lCPE_IDENTIFIER};${lPURL_IDENTIFIER};${SBOM_COMP_BOM_REF};Linux distribution identification module" "${S08_CSV_LOG}"
            lOUTPUT=1
          fi
        fi
      done
    fi
  done < "${CONFIG_DIR}"/distri_id.cfg

  write_log ""
  module_end_log "${FUNCNAME[0]}" "${lOUTPUT}"
}

dlink_image_sign() {
  # the firmware version can be found in /config/buildver
  local lIDENTIFIER="${1:-}"
  local lDLINK_BUILDVER_ARR=()
  local lDLINK_BREV=""
  local lDLINK_BVER=""
  local lDLINK_FW_VER_tmp=""

  mapfile -t lDLINK_BUILDVER_ARR < <(find "${FIRMWARE_PATH}" -xdev -path "*config/buildver")
  for lDLINK_BVER in "${lDLINK_BUILDVER_ARR[@]}"; do
    DLINK_FW_VER=$(grep -E "[0-9]+\.[0-9]+" "${lDLINK_BVER}")
    if ! [[ "${DLINK_FW_VER}" =~ ^v.* ]]; then
      DLINK_FW_VER="v${DLINK_FW_VER}"
    fi
    # -> v2.14
  done

  local lDLINK_BUILDREV_ARR=()
  # probably we can use this in the future. Currently there is no need for it:
  mapfile -t lDLINK_BUILDREV_ARR < <(find "${FIRMWARE_PATH}" -xdev -path "*config/buildrev")
  for lDLINK_BREV in "${lDLINK_BUILDREV_ARR[@]}"; do
    lDLINK_FW_VER_tmp=$(grep -E "^[A-Z][0-9]+" "${lDLINK_BREV}" || true)
    # -> B01
    DLINK_FW_VER="${DLINK_FW_VER}""${lDLINK_FW_VER_tmp}"
    # -> v2.14B01
    # if we have multiple files we only take the first one - this usually happens if we have some packed firmware
    break
  done

  if [[ -n "${DLINK_FW_VER}" ]]; then
    lIDENTIFIER="D-Link ${lIDENTIFIER}"" ${DLINK_FW_VER}"
    # -> D-Link dir-300 v2.14B01
    echo "${lIDENTIFIER}"
  fi
}

get_csv_rule_distri() {
  # this is a temp solution. If this list grows we are going to solve it via a configuration file
  local lVERSION_IDENTIFIER="${1:-}"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER,,}" | tr -dc '[:print:]')"

  ### handle versions of linux distributions:
  # debian 9 (stretch) - installer build 20170615+deb9u5
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(debian) [0-9]+\ \([a-z]+\)\ -\ installer\ build\ [0-9]+\+deb([0-9]+)u([0-9])/:\1:\1_linux:\2\.\3/')"
  # debian 9
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(debian) ([0-9]+(\.[0-9]+)+?).*/:\1:\1_linux:\2/')"
  # Fedora 17 (Beefy Miracle)
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(fedora)\ ([0-9]+).*/:\1project:\1:\2/')"
  # CentOS
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/centos\ linux\ ([0-9]+(\.[0-9]+)+?).*/:centos:centos:\1/')"
  # Ubuntu
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(ubuntu)\ ([0-9]+\,[0-9]+).*/:\1_linux:\1:\2/')"
  # OpenWRT KAMIKAZE r18* -> 8.09.2
  # see also: https://openwrt.org/about/history
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(openwrt)\ (kamikaze)\ r1[4-8][0-9][0-9][0-9].*/:\1:\2:8.09/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(openwrt)\ (backfire)\ r2[0-9][0-9][0-9][0-9].*/:\1:\2:10.03/')"
  # OpenWrt 18.06.2 r7676-cddd7b4c77
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/(openwrt)\ ([0-9]+\.[0-9]+\.[0-9]+)\ (r[0-9]+\-[a-z0-9]+).*/:openwrt:openwrt:\2:\3/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/lede\ ([0-9]+\.[0-9]+\.[0-9]+)(-)?(rc[0-9])?.*/:openwrt:openwrt:\1:\3/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/openwrt\ ([0-9]+\.[0-9]+)/:openwrt:openwrt:\1/')"
  # OpenWrt Attitude Adjustment r7549 -> 12.09
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/openwrt\ attitude\ adjustment\ r([0-9]+).*/:openwrt:openwrt:12\.09/')"
  # d-link dir-300 v2.14b01
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/d-link\ (.*)\ v([0-9].[0-9]+[a-z][0-9]+)/:dlink:\1_firmware:\2/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/d-link\ (.*)\ v([0-9].[0-9]+)/:dlink:\1_firmware:\2:/')"
  # dd-wrt v24-sp2
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/dd-wrt\ v([0-9]+)-?(sp[0-9])?.*/:dd-wrt:dd-wrt:\1:\2/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/dd-wrt\ \#([0-9]+).*/:dd-wrt:dd-wrt:\1/')"
  # iotgoat v1.0
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/iotgoat\ v([0-9]\.[0-9]+)/:iotgoat:iotgoat:\1/')"
  # F5 BigIP
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/big-ip\ ltm\ ([0-9]+(\.[0-9]+)+?)/:f5:big-ip_local_traffic_manager:\1/')"
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/big-ip\ asm\ ([0-9]+(\.[0-9]+)+?)/:f5:big-ip_application_security_manager:\1/')"
  # Yocto linux - e.g.: poky:(yocto:project:reference:distro):2.2:(morty)
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/.*\(yocto:project:reference:distro\):([0-9]+(\.[0-9]+)+?):\(.*\)$/:yoctoproject:yocto:\1/')"
  # Buildroot 2022.01.01
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/buildroot\ ([0-9]+(\.[0-9]+)+?)/:buildroot:buildroot:\1/')"
  #   MikroTik routerOS V2.4 (c) 1999-2001       http://mikrotik.com/
  lVERSION_IDENTIFIER="$(safe_echo "${lVERSION_IDENTIFIER}" | sed -r 's/.*mikrotik\ routeros\ v([0-9]\.[0-9]+).*/:mikrotik:routeros:\1/')"
  lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER// /:}"
  lCSV_RULE="$(safe_echo "${lVERSION_IDENTIFIER}" | tr -dc '[:print:]')"
  echo "${lCSV_RULE}"
}
