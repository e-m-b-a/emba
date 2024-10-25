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

# Description:  Installs binwalk and dependencies for EMBA

IP99_binwalk_default() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component binwalk" && exit 1 )
    INSTALL_APP_LIST=()

    print_tool_info "git" 1
    print_tool_info "wget" 1
    print_tool_info "locales" 1
    print_tool_info "qtbase5-dev" 1
    print_tool_info "build-essential" 1
    print_tool_info "mtd-utils" 1
    print_tool_info "gzip" 1
    print_tool_info "bzip2" 1
    print_tool_info "tar" 1
    print_tool_info "arj" 1
    print_tool_info "lhasa" 1
    print_tool_info "p7zip" 1
    print_tool_info "p7zip-rar" 1
    print_tool_info "p7zip-full" 1
    print_tool_info "cabextract" 1
    print_tool_info "util-linux" 1
    print_tool_info "python3-matplotlib" 1
    # sometimes the python pip installation is needed - probably this will be solved in the future
    # probably it depends on the venv?!?
    print_pip_info "matplotlib"

    # tools only available on Kali Linux:
    if [[ "${OTHER_OS}" -eq 0 ]] && [[ "${UBUNTU_OS}" -eq 0 ]]; then
      # firmware-mod-kit is only available on Kali Linux
      print_tool_info "firmware-mod-kit" 1
    else
      echo -e "${RED}""${BOLD}""Not installing firmware-mod-kit. Your EMBA installation will be incomplete""${NC}"
    fi

    print_tool_info "cramfsswap" 1
    print_tool_info "squashfs-tools" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "liblzma-dev" 1
    print_tool_info "liblzo2-dev" 1
    print_tool_info "sleuthkit" 1
    print_tool_info "default-jdk" 1
    print_tool_info "lzop" 1
    print_tool_info "cpio" 1
    print_tool_info "python3-pip" 1
    print_tool_info "python3-opengl" 1
    print_tool_info "python3-pyqt5" 1
    print_tool_info "python3-pyqt5.qtopengl" 1
    print_tool_info "python3-numpy" 1
    print_tool_info "python3-scipy" 1
    # print_tool_info "python-setuptools" 1
    print_pip_info "setuptools"
    # screcord is currently not available anymore via apt-get
    # Todo: Check if it is needed and we need to find some alternative solution
    # print_tool_info "srecord" 1
    print_tool_info "unrar-free" 1
    print_tool_info "unrar" 1
    # print_tool_info "binwalk" 1
    # print_tool_info "python3-binwalk" 1
    # we install binwalk now from https://github.com/OSPG/binwalk
    print_tool_info "python-is-python3" 1
    print_tool_info "capstone-tool" 1
    print_pip_info "capstone"
    print_tool_info "libcapstone4:amd64" 1
    print_tool_info "python3-capstone" 1
    print_git_info "sasquatch" "devttys0/sasquatch" "The sasquatch project is a set of patches to the standard unsquashfs utility (part of squashfs-tools) that attempts to add support for as many hacked-up vendor-specific SquashFS implementations as possible."
    echo -e "${ORANGE}""devttys0 - sasquatch will be downloaded.""${NC}"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""binwalk, yaffshiv, sasquatch, jefferson, unstuff, cramfs-tools and ubi_reader (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        pip_install "setuptools"
        pip_install "matplotlib"
        pip_install "capstone"

        git clone https://github.com/EMBA-support-repos/binwalk_ospg.git external/binwalk
        cd external/binwalk || ( echo "Could not install EMBA component binwalk" && exit 1 )
        # pip --user makes problems -> lets remove it for now
        sed -i 's/--user //' ./deps.sh
        sed -i 's/python3-distutils\ //' ./deps.sh
        ./deps.sh --yes || ( echo "Could not install EMBA component binwalk" && exit 1 )
        python3 setup.py install || ( echo "Could not install EMBA component binwalk" && exit 1 )
        BINWALK_GIT_HASH=$(git describe --always)
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component binwalk" && exit 1 )

        if ! [[ -d external/cpu_rec ]]; then
          git clone https://github.com/EMBA-support-repos/cpu_rec.git external/cpu_rec
          # this does not make sense for the read only docker container - we have to do it
          # during EMBA startup
          if ! [[ -d "${HOME}"/.config/binwalk/modules/ ]]; then
            mkdir -p "${HOME}"/.config/binwalk/modules/
          fi
          cp -pr external/cpu_rec/cpu_rec.py "${HOME}"/.config/binwalk/modules/
          cp -pr external/cpu_rec/cpu_rec_corpus "${HOME}"/.config/binwalk/modules/
        fi

        # if ! [[ -d external/binwalk/sasquatch ]]; then
        #   mkdir -p external/binwalk
        #   git clone https://github.com/devttys0/sasquatch external/binwalk/sasquatch
        # fi
        # cd external/binwalk/sasquatch || ( echo "Could not install EMBA component sasquatch" && exit 1 )
        # wget https://github.com/devttys0/sasquatch/pull/47.patch
        # patch -p1 < 47.patch
        # CFLAGS="-fcommon -Wno-misleading-indentation" ./build.sh -y
        # cd "${HOME_PATH}" || ( echo "Could not install EMBA component sasquatch" && exit 1 )

        # we have seen issues with the unblob sasquatch version - lets move the binwalk version to another name and link to it
        # during the testing phase. With this in place we are able to install both versions in ||
        if [[ -e /usr/local/bin/sasquatch ]]; then
          echo -e "${GREEN}Backup binwalk sasquatch version to ${ORANGE}/usr/local/bin/sasquatch_binwalk${NC}"
          mv /usr/local/bin/sasquatch /usr/local/bin/sasquatch_binwalk

          if ! [[ -d "${HOME}"/.config/binwalk/config/ ]]; then
            mkdir -p "${HOME}"/.config/binwalk/config/
          fi
          cp ./external/emba_venv/lib/python3.12/site-packages/binwalk-2.4.2+"${BINWALK_GIT_HASH}"-py3.12.egg/binwalk/config/extract.conf "${HOME}"/.config/binwalk/config/

          # sed -i 's/squashfs:sasquatch /squashfs:sasquatch_binwalk /' /usr/local/lib/python3.11/dist-packages/binwalk/config/extract.conf
          sed -i 's/squashfs:sasquatch /squashfs:sasquatch_binwalk /' "${HOME}"/.config/binwalk/config/extract.conf
        fi

        if command -v binwalk > /dev/null ; then
          echo -e "${GREEN}""binwalk installed successfully""${NC}"
        elif [[ ! -f "/usr/local/bin/binwalk" ]] ; then
          echo -e "${ORANGE}""binwalk installation failed - check it manually""${NC}"
        fi
      ;;
    esac
  fi
}
