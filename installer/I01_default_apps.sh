#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs basic toole which are always needed for EMBA and currently have no dedicated installer module

I01_default_apps(){
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]] ; then
    print_tool_info "file" 1
    print_tool_info "jq" 1
    print_tool_info "make" 1
    print_tool_info "tree" 1
    print_tool_info "device-tree-compiler" 1
    print_tool_info "qemu-user-static" 0 "qemu-mips-static"
    #print_tool_info "pylint" 1 # not used anymore
    # libguestfs-tools is needed to mount vmdk images
    print_tool_info "libguestfs-tools" 1
    print_tool_info "ent" 1
    # needed for sshdcc:
    print_tool_info "tcllib" 1
    print_tool_info "u-boot-tools" 1
    print_tool_info "python3-bandit" 1
    print_tool_info "iputils-ping" 1
    # john password cracker
    print_tool_info "john" 1
    print_tool_info "john-data" 1
    # linuxbrew
    print_tool_info "curl" 1
    print_tool_info "git" 1
    print_tool_info "strace" 1

    print_tool_info "rpm" 1

    # python3.10-request
    print_tool_info "python3-pip" 1
    print_pip_info "requests"

    # Ubuntu not installing ping - see https://github.com/e-m-b-a/embark/issues/151
    print_tool_info "iputils-ping" 1

    # diffing firmware
    print_tool_info "colordiff" 1
    print_tool_info "ssdeep" 1
    print_tool_info "xdot" 1

    # exif parser and readpe for windows binary analysis
    print_tool_info "libimage-exiftool-perl" 1
    print_tool_info "readpe" 1

    # tools only available on Kali Linux:
    if [[ "${OTHER_OS}" -eq 0 ]] && [[ "${UBUNTU_OS}" -eq 0 ]]; then
      print_tool_info "metasploit-framework" 1
    else
      echo -e "${RED}""${BOLD}""Not installing metasploit-framework. Your EMBA installation will be incomplete""${NC}"
    fi

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These applications will be installed/updated!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        echo
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        # install brew installer - used later for cyclonex in IF20 installer
        echo "[*] Installing linuxbrew ..."
        if ! grep -q linuxbrew /etc/passwd; then
          useradd -m -s /bin/bash linuxbrew
        fi
        usermod -aG sudo linuxbrew
        if [[ -d /home/linuxbrew/.linuxbrew ]]; then
          rm -r /home/linuxbrew/.linuxbrew
        fi
        mkdir -p /home/linuxbrew/.linuxbrew
        chown -R linuxbrew: /home/linuxbrew/.linuxbrew
        # sudo -u linuxbrew CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
        # nosemgrep
        sudo -u linuxbrew CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Install Rust (used from cwe_checker and binwalk)
        rm "${HOME}"/.cargo -r -f
        rm "${HOME}"/.config -r -f
        rm external/rustup -r -f

        curl https://sh.rustup.rs -sSf | sh -s -- -y
        # shellcheck disble=SC1091
        . "${HOME}"/.cargo/env

        export PATH="${PATH}":"${HOME}"/.cargo/bin


        pip_install "requests" "-U"
      ;;
    esac
  fi
}
