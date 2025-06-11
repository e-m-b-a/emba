#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Installs cve-bin-tool including database for offline work

IF17_cve_bin_tool() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    INSTALL_APP_LIST=()

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] ; then
      print_tool_info "gsutil"
      print_tool_info "libjson-pp-perl"
      print_pip_info "protobuf"
      # print_pip_info "cve_bin_tool"
      print_git_info "cve-bin-tool" "https://github.com/EMBA-support-repos/cve-bin-tool.git" "cve-bin-tool"
    fi

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}"" cve-bin-tool will be downloaded (if not already on the system)!""${NC}"
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        # cve-bin-tool installation
        echo -e "${ORANGE}""${BOLD}""Install cve-bin-tool""${NC}"
        git clone https://github.com/EMBA-support-repos/cve-bin-tool.git external/cve-bin-tool
        cd external/cve-bin-tool || ( echo "Could not install EMBA component cve-bin-tool" && exit 1 )
        pip install -U -r requirements.txt
        python3 -m pip install -e .

        # we need a more up to date protobuf for the android extractor -> lets update it now
        pip_install "protobuf==5.*"

        echo "[*] Preparing test data ..."
        # preparing test data to ensure our CVE database is working as expected
        echo "product,vendor,version" > "./cve_bin_tool_health_check.csv"
        echo "busybox,NOTDEFINED,1.14.1" >> "./cve_bin_tool_health_check.csv"

        if ! [[ -d "${HOME}"/.cache/cve-bin-tool ]]; then
          mkdir "${HOME}"/.cache/cve-bin-tool
        fi

        if [[ -f /installer/cve-database.db ]]; then
          echo "[*] Testing the CVE database with the following test data:"
          cat ./cve_bin_tool_health_check.csv

          echo "[*] Importing CVE database from /installer/cve-database.db"
          python3 ./cve_bin_tool/cli.py --import /installer/cve-database.db || true
          # testing import
          python3 ./cve_bin_tool/cli.py -i ./cve_bin_tool_health_check.csv --disable-version-check --disable-validation-check --no-0-cve-report --offline -f csv -o /tmp/cve_bin_tool_health_check_results || true

          echo "[*] CVE query results for busybox query after initial import:"
          cat "/tmp/cve_bin_tool_health_check_results.csv"
          rm "/tmp/cve_bin_tool_health_check_results.csv"
        else
          echo "[-] WARNING: No CVE database update file available from installer directory /installer/cve-database.db"
        fi

        echo "[*] Updating CVE database"
        python3 ./cve_bin_tool/cli.py --update now -n json-mirror || true
        # testing db update
        python3 ./cve_bin_tool/cli.py -i ./cve_bin_tool_health_check.csv --disable-version-check --disable-validation-check --no-0-cve-report --offline -f csv -o /tmp/cve_bin_tool_health_check_results || true

        echo "[*] CVE query results for busybox query after database update:"
        cat /tmp/cve_bin_tool_health_check_results.csv
        rm /tmp/cve_bin_tool_health_check_results.csv

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-bin-tool" && exit 1 )
        echo "[*] Exporting CVE database"

        python3 external/cve-bin-tool/cve_bin_tool/cli.py --export external/cve-bin-tool/cve-database.db || true

        # cleanup
        rm -r "${HOME}"/.cache/cve-bin-tool
        rm external/cve-bin-tool/cve_bin_tool_health_check.csv

        if [[ -f external/cve-bin-tool/cve-database.db ]]; then
          echo -e "${GREEN}[+] CVE database installed${NC}"
        else
          echo -e "${ORANGE}ERROR: Could not build cve-bin-tool database${NC}"
          exit 1
        fi
      ;;
    esac
  fi
}
