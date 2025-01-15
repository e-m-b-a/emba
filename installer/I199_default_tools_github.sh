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

# Description:  Installs different open source tools from github

I199_default_tools_github() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    print_file_info "linux-exploit-suggester" "Linux privilege escalation auditing tool" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
    print_file_info "checksec" "Check the properties of executables (like PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
    print_file_info "sshdcc" "Check SSHd configuration files" "https://raw.githubusercontent.com/sektioneins/sshdcc/master/sshdcc" "external/sshdcc"
    print_file_info "sudo-parser.pl" "Parses and tests sudoers configuration files" "https://raw.githubusercontent.com/CiscoCXSecurity/sudo-parser/master/sudo-parser.pl" "external/sudo-parser.pl"
    print_file_info "pixd" "pixd is a tool for visualizing binary data using a colour palette." "https://raw.githubusercontent.com/EMBA-support-repos/pixd_image/refs/heads/master/pixd.c" "external/pixd"
    print_file_info "progpilot" "progpilot is a tool for static security tests on php files." "https://github.com/designsecurity/progpilot/releases/download/v1.0.2/progpilot_v1.0.2.phar" "external/progpilot"
    print_file_info "EnGenius decryptor" "Decrypts EnGenius firmware files." "https://raw.githubusercontent.com/EMBA-support-repos/enfringement/main/decrypt.py" "external/engenius-decrypt.py"

    print_pip_info "pillow"
    print_git_info "jchroot" "EMBA-support-repos/jchroot" "jchroot - a chroot with more isolation"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These applications (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        download_file "linux-exploit-suggester" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
        download_file "checksec" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
        download_file "sshdcc" "https://raw.githubusercontent.com/sektioneins/sshdcc/master/sshdcc" "external/sshdcc"
        download_file "sudo-parser.pl" "https://raw.githubusercontent.com/CiscoCXSecurity/sudo-parser/master/sudo-parser.pl" "external/sudo-parser.pl"
        download_file "progpilot" "https://github.com/designsecurity/progpilot/releases/download/v1.0.2/progpilot_v1.0.2.phar" "external/progpilot"
        download_file "EnGenius decryptor" "https://raw.githubusercontent.com/EMBA-support-repos/enfringement/main/decrypt.py" "external/engenius-decrypt.py"

        # pixd installation
        pip_install "pillow"
        echo -e "\\n""${ORANGE}""${BOLD}""Downloading of pixd""${NC}"
        git clone https://github.com/EMBA-support-repos/pixd_image.git ./external/pixd/
        cd ./external/pixd/ || ( echo "Could not install EMBA component pixd" && exit 1 )
        make
        mv pixd ../pixde
        mv pixd_png.py ../pixd_png.py
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component pixd" && exit 1 )
        rm -r ./external/pixd/
        # pixd installation finished

        # jchroot
        echo -e "\\n""${ORANGE}""${BOLD}""Download and install jchroot""${NC}"
        if [[ -d "external/jchroot" ]]; then
          rm -r external/jchroot
        fi
        git clone https://github.com/EMBA-support-repos/jchroot.git external/jchroot
        cd ./external/jchroot/ || ( echo "Could not install EMBA component jchroot" && exit 1 )
        make
        if [[ -e ./jchroot ]] && [[ -e "/usr/sbin/jchroot" ]]; then
          rm /usr/sbin/jchroot
        fi
        if [[ -e ./jchroot ]]; then
          cp -r jchroot /usr/sbin/
        fi
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component jchroot" && exit 1 )
      ;;
    esac
  fi
}
