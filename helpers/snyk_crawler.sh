#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

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
# Author(s): Michael Messner, Endri Hoxha

# Description:  Update script for Snyk Exploit/PoC collection


URL="https://security.snyk.io/vuln"
LINKS="snyk_adv_links.txt"
SAVE_PATH="/tmp/snyk"
EMBA_CONFIG_PATH="./config/"

if ! [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m"  # no color

if [[ -f "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv ]]; then
  PoC_CNT_BEFORE="$(wc -l "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv | awk '{print $1}')"
  echo -e "${GREEN}[+] Found ${ORANGE}${PoC_CNT_BEFORE}${GREEN} advisories with PoC code (before update)"
fi

if [[ -d "${SAVE_PATH}" ]]; then
  rm -r "${SAVE_PATH}"
fi
if ! [[ -d "${SAVE_PATH}/vuln" ]]; then
  mkdir -p "${SAVE_PATH}/vuln"
fi

echo "[*] Generating URL list for snyk advisories"
ID=1
# this approach will end after 31 pages:
while lynx -useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.79 Safari/537.1" -dump -hiddenlinks=listonly "${URL}"/"${ID}" | grep "${URL}/SNYK" >> "${SAVE_PATH}"/"${LINKS}"; do
  echo -e "[*] Generating list of URLs of Snyk advisory page ${ORANGE}${ID}${NC} / ${ORANGE}${URL}${ID}${NC}"
  ((ID+=1))
done

# some filters we can use to get further results:
APPLICATIONS=("cargo" "cocoapods" "composer" "golang" "hex" "maven" "npm" "nuget" "pip" \
  "rubygems" "unmanaged" "linux" "alpine" "amzn" "centos" "debian" "oracle" "rhel" \
  "sles" "ubuntu")

for APPLICATION in "${APPLICATIONS[@]}"; do
  ID=1
  while lynx -useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.79 Safari/537.1" -dump -hiddenlinks=listonly "${URL}"/"${APPLICATION}"/"${ID}" | grep "${URL}/SNYK" >> "${SAVE_PATH}"/"${LINKS}"; do
    echo -e "[*] Generating list of URLs of Snyk advisory page ${ORANGE}${ID}${NC} / application ${ORANGE}${APPLICATION}${NC} / URL ${ORANGE}${URL}/${APPLICATION}/${ID}${NC}"
    ((ID+=1))
  done
done

# as we do not reach all the advisories via this search mechanism we also load the current state
# and use the URLs from it for further crawling:
if [[ -f "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv ]]; then
  echo -e "[*] Adding already known URLs from current configuration file"
  # remove first line which is the header
  cut -d\; -f3 "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv | sed 1d >> "${SAVE_PATH}"/"${LINKS}"
else
  echo -e "${RED}[-] WARNING: No Snyk configuration file found"
fi

# remove the numbering at the beginning of every entry:
sed 's/.*http/http/' "${SAVE_PATH}"/"${LINKS}" | sort -u > "${SAVE_PATH}"/"${LINKS}"_sorted

ADV_CNT="$(wc -l "${SAVE_PATH}"/"${LINKS}"_sorted | awk '{print $1}')"
echo -e "[*] Detected ${ORANGE}${ADV_CNT}${NC} advisories for download"
echo ""

ID=1
while read -r ADV; do
  ((ID+=1))
  FILENAME="$(echo "${ADV}" | rev | cut -d '/' -f1 | rev)"
  if [[ -f "${SAVE_PATH}/vuln/${FILENAME}" ]]; then
    echo -e "[-] Already downloaded ${ORANGE}${FILENAME}${NC}"
    continue
  fi
  echo -e "[*] Downloading ${ORANGE}${FILENAME}${NC} (${ORANGE}${ID}${NC}/${ORANGE}${ADV_CNT}${NC}) to ${ORANGE}${SAVE_PATH}/vuln/${FILENAME}${NC}"
  lynx -useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.79 Safari/537.1" -dump -hiddenlinks=listonly "${ADV}" > "${SAVE_PATH}"/vuln/"${FILENAME}"
done < "${SAVE_PATH}"/"${LINKS}"_sorted

echo -e "[*] Finished downloading ${ORANGE}${ADV_CNT}${NC} advisories to ${ORANGE}${SAVE_PATH}/vuln${NC}"
echo ""

echo -e "[*] The following advisories have PoC code included:"
PoC_CNT=0
echo "CVE;advisory name;advisory URL;unknown PoC;Github PoC;Curl PoC;XML PoC;" > "${SAVE_PATH}"/Snyk_PoC_results.csv

while IFS= read -r -d '' ADV; do
  PoC_PoC="no"
  PoC_GH="no"
  PoC_EDB="no"
  PoC_CURL="no"
  PoC_XML="no"
  CVE="NA"
  ADV_NAME=$(basename "${ADV}")
  ADV_URL="${URL}"/"${ADV_NAME}"

  # unsure if this is good enough:
  PoC_PoC=$(grep -c -a "PoC" "${ADV}")
  PoC="${PoC_PoC}"
  if [[ "${PoC_PoC}" -gt 0 ]]; then
    PoC_PoC="yes"
  else
    PoC_PoC="no"
  fi
  # GitHub PoC references:
  PoC_GH=$(grep -a -c "GitHub PoC" "${ADV}")
  ((PoC+="${PoC_GH}"))
  if [[ "${PoC_GH}" -gt 0 ]]; then
    PoC_GH="yes"
  else
    PoC_GH="no"
  fi
  # removed exploit-db as we already have it in EMBA
  # exploit-db references:
  # PoC_EDB=$(grep -a -c -E "https://www.exploit-db.com/exploits/[0-9]+" "${ADV}")
  # ((PoC+="$PoC_EDB"))
  # if [[ "$PoC_EDB" -gt 0 ]]; then
  #  PoC_EDB="yes"
  # else
  #  PoC_EDB="no"
  # fi
  # curl http exploits:
  PoC_CURL=$(grep -a -c "curl http" "${ADV}")
  ((PoC+="${PoC_CURL}"))
  if [[ "${PoC_CURL}" -gt 0 ]]; then
    PoC_CURL="yes"
  else
    PoC_CURL="no"
  fi
  # xml exploits:
  PoC_XML=$(grep -a -c "For example the below code contains" "${ADV}")
  ((PoC+="${PoC_XML}"))
  if [[ "${PoC_XML}" -gt 0 ]]; then
    PoC_XML="yes"
  else
    PoC_XML="no"
  fi
  # we check only for valid cves and remove "id=" with cut
  mapfile -t CVEs < <(grep -a -o -E "id=CVE-[0-9]{4}-[0-9]+" "${ADV}" | sort -u | cut -c 4-)

  if [[ "${PoC}" -gt 0 ]] && [[ "${#CVEs[@]}" -gt 0 ]]; then
    for CVE in "${CVEs[@]}"; do
      echo -e "[+] Found PoC for ${ORANGE}${CVE}${NC} in advisory ${ORANGE}${ADV_NAME}${NC} (unknown PoC: ${ORANGE}${PoC_PoC}${NC} / Github: ${ORANGE}${PoC_GH}${NC} / exploit-db: ${ORANGE}${PoC_EDB}${NC} / Curl: ${ORANGE}${PoC_CURL}${NC} / XML: ${ORANGE}${PoC_XML}${NC})"
      echo "${CVE};${ADV_NAME};${ADV_URL};${PoC_PoC};${PoC_GH};${PoC_CURL};${PoC_XML};" >> "${SAVE_PATH}"/Snyk_PoC_results.csv
      ((PoC_CNT+=1))
    done
  fi
done < <(find "${SAVE_PATH}"/vuln/ -type f -print0)

sort -nr -o "${SAVE_PATH}"/Snyk_PoC_results.csv "${SAVE_PATH}"/Snyk_PoC_results.csv


if [[ -f "${SAVE_PATH}"/Snyk_PoC_results.csv ]] && [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  uniq "${SAVE_PATH}"/Snyk_PoC_results.csv > "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv
  rm -r "${SAVE_PATH}"
  echo -e "${GREEN}[+] Successfully stored generated PoC file in EMBA configuration directory."
else
  echo "[-] Not able to copy generated PoC file to configuration directory ${EMBA_CONFIG_PATH}"
fi

echo -e "${GREEN}[+] Found ${ORANGE}${PoC_CNT_BEFORE}${GREEN} advisories with PoC code (before update)."
echo ""
echo -e "${GREEN}[+] Found ${ORANGE}${PoC_CNT}${GREEN} advisories with PoC code (after update)."
