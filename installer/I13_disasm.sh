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

# Description:  Installs binutils and other tools like radare2 for s12-14

I13_disasm() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    BINUTIL_VERSION_NAME="binutils-2.35.1"
    CAPA_VERSION="9.2.1"

    INSTALL_APP_LIST=()

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] ; then
      print_file_info "${BINUTIL_VERSION_NAME}" "The GNU Binutils are a collection of binary tools." "https://ftp.gnu.org/gnu/binutils/${BINUTIL_VERSION_NAME}.tar.gz" "external/${BINUTIL_VERSION_NAME}.tar.gz" "external/objdump"
      print_file_info "Capa" "Capa - Open-source tool to identify capabilities in executable files." "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip" "external/capa-v${CAPA_VERSION}-linux.zip"
      print_tool_info "texinfo" 1
      print_tool_info "git" 1
      print_tool_info "wget" 1
      print_tool_info "gcc" 1
      print_tool_info "make" 1
      print_tool_info "build-essential" 1
      print_tool_info "gawk" 1
      print_tool_info "bison" 1
      print_tool_info "debuginfod" 1
      print_tool_info "python3" 1
      print_tool_info "python-is-python3" 1
      print_tool_info "libzip-dev" 1
      print_tool_info "meson" 1
      # if [[ "${OTHER_OS}" -eq 0 ]] && [[ "${UBUNTU_OS}" -eq 0 ]]; then
      #  print_tool_info "radare2" 1
      # else
      #  echo -e "${RED}""${BOLD}""Not installing radare2. Your EMBA installation will be incomplete""${NC}"
      # fi
    fi

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""${BINUTIL_VERSION_NAME}"" will be downloaded (if not already on the system) and objdump compiled!""${NC}"
    fi

    case ${ANSWER:0:1} in
      y|Y )
        # apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        if ! [[ -f "external/capa" ]]; then
          download_file "Capa" "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip" "external/capa-v${CAPA_VERSION}-linux.zip"
          unzip external/capa-v"${CAPA_VERSION}"-linux.zip -d external || ( echo "Could not install EMBA component Capa" && exit 1 )
          rm external/capa-v"${CAPA_VERSION}"-linux.zip
        fi

        if ! [[ -f "external/objdump" ]] ; then
          download_file "${BINUTIL_VERSION_NAME}" "https://ftp.gnu.org/gnu/binutils/${BINUTIL_VERSION_NAME}.tar.gz" "external/${BINUTIL_VERSION_NAME}.tar.gz"
          if [[ -f "external/${BINUTIL_VERSION_NAME}.tar.gz" ]] ; then
            tar -zxf external/"${BINUTIL_VERSION_NAME}".tar.gz -C external
            cd external/"${BINUTIL_VERSION_NAME}"/ || ( echo "Could not install EMBA component binutils" && exit 1 )
            echo -e "${ORANGE}""${BOLD}""Compile objdump""${NC}"
            ./configure --enable-targets=all
            make
            cd "${HOME_PATH}" || ( echo "Could not install EMBA component binutils" && exit 1 )
          fi
          if [[ -f "external/${BINUTIL_VERSION_NAME}/binutils/objdump" ]] ; then
            mv "external/${BINUTIL_VERSION_NAME}/binutils/objdump" "external/objdump"
            rm -R "external/""${BINUTIL_VERSION_NAME}"
            rm "external/""${BINUTIL_VERSION_NAME}"".tar.gz"
            if [[ -f "external/objdump" ]] ; then
              echo -e "${GREEN}""objdump installed successfully""${NC}"
            fi
          else
            echo -e "${ORANGE}""objdump installation failed - check it manually""${NC}"
          fi
        else
          echo -e "${GREEN}""objdump already installed - no further action performed.""${NC}"
        fi

        # radare2
        echo -e "${ORANGE}""${BOLD}""Install radare2""${NC}"
        # apt-get install radare2 libradare2-dev libradare2-common libradare2-5.0.0 -y
        git clone https://github.com/radareorg/radare2.git external/radare2
        cd external/radare2 || ( echo "Could not install EMBA component radare2" && exit 1 )
        # we remove the line to execute the script again as sudo user (non root)
        # this mechanism is not working with our docker container and results in an endless loop
        sed -i '/exec sudo -u.*install.sh \$\*/d' sys/install.sh
        sys/install.sh
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component radare2" && exit 1 )

        echo -e "${ORANGE}""${BOLD}""Install radare2 package r2dec""${NC}"
        # r2pm init
        # r2pm update
        # r2pm install r2dec
        # r2pm -cgi r2dec
        r2pm -Uci r2dec
        echo -e "${ORANGE}""${BOLD}""Installed r2 plugins:""${NC}"
        r2pm -l
        # cp -pri /root/.local/share/radare2 external/radare_local_bak
      ;;
    esac
  fi
}
