#!/bin/bash

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
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs common aggregator tools for EMBA

IF50_aggregator_common() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    INSTALL_APP_LIST=()
    print_tool_info "python3-pip" 1
    print_tool_info "net-tools" 1
    print_tool_info "exploitdb" 1
    print_pip_info "cve-searchsploit"
    # jo is used to build the sbom
    print_tool_info "jo" 1
    echo -e "\\n""${ORANGE}""${BOLD}""cyclonedx""${NC}"
    echo -e "${ORANGE}""cyclonedx sbom converter will be installed.""${NC}"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""cyclonedx, net-tools, pip3, cve-search and cve_searchsploit (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        pip_install "cve_searchsploit"

        # we try to avoid downloading the exploit-database multiple times:
        CVE_SEARCH_PATH=$(pip3 show cve-searchsploit | grep "Location" | awk '{print $2}')
        if [[ -d "${CVE_SEARCH_PATH}""/cve_searchsploit/exploit-database" ]] && [[ -d "/usr/share/exploitdb" ]]; then
          rm -r "${CVE_SEARCH_PATH}""/cve_searchsploit/exploit-database"
        fi
        if [[ -d "/usr/share/exploitdb" ]]; then
          ln -s "/usr/share/exploitdb" "${CVE_SEARCH_PATH}""/cve_searchsploit/exploit-database"
        fi

        echo -e "\\n""${MAGENTA}""${BOLD}""Updating cve_searchsploit database mapping.""${NC}"
        cve_searchsploit -u

        echo -e "[*] Installing cyclonedx-cli for converting SBOMs"
        if [[ -d "/home/linuxbrew/.linuxbrew/bin" ]]; then
          cd /home/linuxbrew/ || ( echo "Could not install EMBA component cyclonedx-cli" && exit 1 )
          sudo -u linuxbrew NONINTERACTIVE=1 /home/linuxbrew/.linuxbrew/bin/brew install cyclonedx/cyclonedx/cyclonedx-cli
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component cyclonedx-cli" && exit 1 )
        else
          echo -e "${ORANGE}""WARNING: Brew installation not found - skipping cyclonedx installation.""${NC}"
        fi
      ;;
    esac
  fi
  # we were running into issues that this package was removed somehow during the installation process
  # Todo: figure out why and solve it somehow
  apt-get install p7zip-full -y
}
