#!/bin/bash

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
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs Freetz-NG and dependencies for extracting AVM firmware

IP12_avm_freetz_ng_extract() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "$HOME_PATH" || ( echo "Could not install EMBA component Freetz-NG" && exit 1 )
  
    print_file_info "execstack" "execstack for Freetz-NG" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/execstack_0.0.20131005-1+b10_amd64.deb"
    print_tool_info "wget" 1
    print_tool_info "gcc" 1
    print_tool_info "make" 1
    print_tool_info "automake" 1
    print_tool_info "autoconf" 1
    print_tool_info "bison" 1
    print_tool_info "bzip2" 1
    print_tool_info "file" 1
    print_tool_info "flex" 1
    print_tool_info "g++" 1
    print_tool_info "gawk" 1
    print_tool_info "gettext" 1
    print_tool_info "libtool" 1
    print_tool_info "libtool-bin" 1
    print_tool_info "pkg-config" 1
    print_tool_info "pkgconf" 1
    print_tool_info "python3" 1
    print_tool_info "unzip" 1
    print_tool_info "subversion" 1
    print_tool_info "libncurses5-dev" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "libacl1-dev" 1
    print_tool_info "libcap-dev" 1
    print_tool_info "bc" 1
    print_tool_info "rsync" 1
    print_tool_info "kmod" 1
    print_tool_info "libelf1" 1
    print_tool_info "uuid-dev" 1
    print_tool_info "libssl-dev" 1
    print_tool_info "libgnutls28-dev" 1
    print_tool_info "libsqlite3-dev" 1
    print_tool_info "gcc-multilib" 1
    print_tool_info "python-is-python3" 1
    print_file_info "fitimg" "fit image extractor" "https://boxmatrix.info/hosted/hippie2000/fitimg-0.8.tar.gz" "external/fitimg-0.8.tar.gz"
    print_tool_info "libstring-crc32-perl" 1
    print_tool_info "liblzma-dev" 1
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The Freetz-NG dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
  
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        if ! grep -q freetzuser /etc/passwd; then
          useradd -m freetzuser
          usermod -a -G "${ORIG_GROUP}" freetzuser
          passwd -d freetzuser
        fi
        download_file "execstack" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/execstack_0.0.20131005-1+b10_amd64.deb"
        dpkg -i external/execstack_0.0.20131005-1+b10_amd64.deb
        rm external/execstack_0.0.20131005-1+b10_amd64.deb

        if ! [[ -d external/freetz-ng ]]; then
          if [[ -d /tmp/freetz-ng ]]; then
            rm -r /tmp/freetz-ng
          fi

          su - freetzuser -c "git clone https://github.com/Freetz-NG/freetz-ng.git /tmp/freetz-ng"
          su - freetzuser -c "cd /tmp/freetz-ng/ && make allnoconfig"
          # we currently running into an error that does not hinder us in using Freetz-NG
          # sudo -u freetzuser make || true
          su - freetzuser -c "cd /tmp/freetz-ng/ && make tools"
          cd "$HOME_PATH" || ( echo "Could not install EMBA component Freetz-NG" && exit 1 )
          mv /tmp/freetz-ng external/
          chown -R root:root external/freetz-ng
          if [[ "$IN_DOCKER" -eq 1 ]]; then
            # do some cleanup of the docker image
            userdel freetzuser
            if [[ -d "external/freetz-ng/source" ]]; then
              echo -e "${ORANGE}[*] Removing freetz-ng source directory$NC"
              rm -r "external/freetz-ng/source"
            fi
            if [[ -d "external/freetz-ng/docs" ]]; then
              echo -e "${ORANGE}[*] Removing freetz-ng docs directory$NC"
              rm -r "external/freetz-ng/docs"
            fi
            if [[ -d "external/freetz-ng/toolchain" ]]; then
              echo -e "${ORANGE}[*] Removing freetz-ng toolchain directory$NC"
              rm -r "external/freetz-ng/toolchain"
            fi
            if [[ -d "external/freetz-ng/.git" ]]; then
              echo -e "${ORANGE}[*] Removing freetz-ng .git directory$NC"
              rm -r "external/freetz-ng/.git"
            fi
            if [[ -d "external/freetz-ng/make" ]]; then
              echo -e "${ORANGE}[*] Removing freetz-ng make directory$NC"
              rm -r "external/freetz-ng/make"
            fi
          fi
        else
          echo -e "${ORANGE}Found freetz directory ... Not touching it$NC"
        fi

        # fitimg installation
        cd "$HOME_PATH" || ( echo "Could not install EMBA component fitimg" && exit 1 )
        download_file "fitimg" "https://boxmatrix.info/hosted/hippie2000/fitimg-0.8.tar.gz" "external/fitimg-0.8.tar.gz"
        if [[ -f "external/fitimg-0.8.tar.gz" ]]; then
          echo -e "${ORANGE}[*] Installing fitimg$NC"
          tar -zxv -f "external/fitimg-0.8.tar.gz" -C external
          rm "external/fitimg-0.8.tar.gz"
        else
          echo "Warning: fitimg download failed"
          exit 1
        fi
      ;;
    esac
  fi
}
