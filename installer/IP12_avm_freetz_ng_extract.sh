#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
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
  
    print_file_info "execstack" "execstack for Freetz-NG" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/freetz-ng/execstack_0.0.20131005-1+b10_amd64.deb"
    print_tool_info "python3" 1
    print_tool_info "python-is-python3" 1
    print_tool_info "pv" 1
    print_tool_info "cpio" 1
    print_tool_info "rsync" 1
    print_tool_info "kmod" 1
    # print_tool_info "execstack" 1
    print_tool_info "libzstd-dev" 1
    print_tool_info "unar" 1
    print_tool_info "inkscape" 1
    print_tool_info "imagemagick" 1
    print_tool_info "graphicsmagick" 1
    print_tool_info "subversion" 1
    print_tool_info "git" 1
    print_tool_info "bc" 1
    print_tool_info "unrar" 1
    print_tool_info "wget" 1
    print_tool_info "sudo" 1
    print_tool_info "gcc" 1
    print_tool_info "g++" 1
    print_tool_info "binutils" 1
    print_tool_info "autoconf" 1
    print_tool_info "automake" 1
    print_tool_info "autopoint" 1
    print_tool_info "libtool-bin" 1
    print_tool_info "make" 1
    print_tool_info "bzip2" 1
    print_tool_info "libncurses5-dev" 1
    print_tool_info "libreadline-dev" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "flex" 1
    print_tool_info "bison" 1
    print_tool_info "patch" 1
    print_tool_info "texinfo" 1
    print_tool_info "tofrodos" 1
    print_tool_info "gettext" 1
    print_tool_info "pkg-config" 1
    print_tool_info "ecj" 1
    print_tool_info "fastjar" 1
    print_tool_info "perl" 1
    print_tool_info "libstring-crc32-perl" 1
    print_tool_info "ruby" 1
    print_tool_info "gawk" 1
    print_tool_info "python2" 1
    print_tool_info "libusb-dev" 1
    print_tool_info "unzip" 1
    print_tool_info "intltool" 1
    print_tool_info "libacl1-dev" 1
    print_tool_info "libcap-dev" 1
    print_tool_info "libc6-dev-i386" 1
    print_tool_info "lib32ncurses5-dev" 1
    print_tool_info "gcc-multilib" 1
    print_tool_info "bsdmainutils" 1
    print_tool_info "lib32stdc++6" 1
    print_tool_info "libglib2.0-dev" 1
    print_tool_info "ccache" 1
    print_tool_info "cmake" 1
    print_tool_info "lib32z1-dev" 1
    print_tool_info "libssl-dev" 1
    print_tool_info "uuid-dev" 1
    print_tool_info "libgnutls28-dev" 1
    print_tool_info "libsqlite3-dev" 1
    print_tool_info "sqlite3" 1
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The Freetz-NG dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
  
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        if ! grep -q freetzuser /etc/passwd; then
          useradd -m freetzuser
          usermod -a -G "${ORIG_GROUP}" freetzuser
        fi
        download_file "execstack" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/execstack_0.0.20131005-1+b10_amd64.deb"
        dpkg -i external/execstack_0.0.20131005-1+b10_amd64.deb
        rm external/execstack_0.0.20131005-1+b10_amd64.deb

        if ! [[ -d external/freetz-ng ]]; then
          mkdir external/freetz-ng

          chown -R freetzuser:freetzuser external/freetz-ng
          chmod 777 -R external/freetz-ng
          su freetzuser -c "git clone https://github.com/Freetz-NG/freetz-ng.git external/freetz-ng"

          cd external/freetz-ng || ( echo "Could not install EMBA component Freetz-NG" && exit 1 )

          sudo -u freetzuser make allnoconfig
          # we currently running into an error that does not hinder us in using Freetz-NG
          sudo -u freetzuser make || true
          sudo -u freetzuser make tools
          cd "$HOME_PATH" || ( echo "Could not install EMBA component Freetz-NG" && exit 1 )
          chown -R root:root external/freetz-ng
          userdel freetzuser
          if [[ -d external/freetz-ng/source ]]; then
            echo "[*] Removing freetz-ng source directory"
            rm -r external/freetz-ng/source
          fi
          if [[ -d external/freetz-ng/docs ]]; then
            echo "[*] Removing freetz-ng docs directory"
            rm -r external/freetz-ng/docs
          fi
          if [[ -d external/freetz-ng/toolchain ]]; then
            echo "[*] Removing freetz-ng toolchain directory"
            rm -r external/freetz-ng/toolchain
          fi
          if [[ -d external/freetz-ng/.git ]]; then
            echo "[*] Removing freetz-ng .git directory"
            rm -r external/freetz-ng/.git
          fi
        else
          echo -e "${ORANGE}Found freetz directory ... Not touching it$NC"
        fi
      ;;
    esac
  fi
}
