#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Installs unblob and dependencies for EMBA

IP61_unblob() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component unblob" && exit 1 )
    INSTALL_APP_LIST=()

    print_tool_info "python3-pip" 1
    print_tool_info "libpython3-dev" 1
    print_tool_info "zlib1g" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "liblzo2-2" 1
    print_tool_info "liblzo2-dev" 1
    print_tool_info "python3-lzo" 1
    print_tool_info "e2fsprogs" 1
    print_tool_info "gcc" 1
    print_tool_info "git" 1
    # print_tool_info "img2simg" 1
    print_tool_info "android-sdk-libsparse-utils" 1
    print_tool_info "liblzo2-dev" 1
    print_tool_info "lz4"
    print_tool_info "lziprecover" 1
    print_tool_info "lzop" 1
    print_tool_info "p7zip-full" 1
    print_tool_info "unar" 1
    print_tool_info "xz-utils" 1
    print_tool_info "zlib1g-dev" 1
    # print_tool_info "libmagic1" 1
    print_tool_info "libhyperscan5" 1
    print_tool_info "libhyperscan-dev" 1
    print_tool_info "zstd" 1
    print_tool_info "python3-magic" 1
    print_tool_info "pkg-config" 1
    print_tool_info "pkgconf" 1
    print_tool_info "erofs-utils" 1
    print_tool_info "partclone" 1
    # print_pip_info "cmake"
    print_tool_info "python3-lief" 1
    # print_pip_info "unblob"
    print_tool_info "unblob" 1

    print_file_info "sasquatch_1.0_amd64.deb" "sasquatch_1.0_amd64.deb" "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_amd64.deb" "external/sasquatch_1.0_amd64.deb"

    # print_file_info "libext2fs2_1.47.0-3.ok2_amd64.deb" "libext2fs2_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_amd64.deb" "external/libext2fs2_1.47.0-3.ok2_amd64.deb"
    # print_file_info "e2fsprogs_1.47.0-3.ok2_amd64.deb" "e2fsprogs_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_amd64.deb" "external/e2fsprogs_1.47.0-3.ok2_amd64.deb"
    # print_file_info "libss2_1.47.0-3.ok2_amd64.deb" "libss2_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_amd64.deb" "external/libss2_1.47.0-3.ok2_amd64.deb"

    # print_git_info "unblob" "EMBA-support-repos/unblob" "Unblob is a powerful firmware extractor"

    # echo -e "${ORANGE}""Unblob will be downloaded and installed via poetry.""${NC}"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""unblob with all dependencies (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component unblob" && exit 1 )

        download_file "sasquatch_1.0_amd64.deb" "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_amd64.deb" "external/sasquatch_1.0_amd64.deb"
        # download_file "libext2fs2_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_amd64.deb" "external/libext2fs2_1.47.0-3.ok2_amd64.deb"
        # download_file "libss2_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_amd64.deb" "external/libss2_1.47.0-3.ok2_amd64.deb"
        # download_file "e2fsprogs_1.47.0-3.ok2_amd64.deb" "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_amd64.deb" "external/e2fsprogs_1.47.0-3.ok2_amd64.deb"

        dpkg -i external/sasquatch_1.0_amd64.deb
        # dpkg -i external/libss2_1.47.0-3.ok2_amd64.deb
        # dpkg -i external/libext2fs2_1.47.0-3.ok2_amd64.deb
        # dpkg -i external/e2fsprogs_1.47.0-3.ok2_amd64.deb

        # rm -f external/sasquatch_1.0_amd64.deb
        # rm -f external/libext2fs2_1.47.0-3.ok2_amd64.deb
        # rm -f external/e2fsprogs_1.47.0-3.ok2_amd64.deb
        # rm -f external/libss2_1.47.0-3.ok2_amd64.deb

        # pip_install "cmake"
        # pip_install "unblob"

        # install poetry
        # python3 -m pip install --upgrade poetry --break-system-packages

        # if ! [[ -d external/unblob ]]; then
        #  git clone https://github.com/EMBA-support-repos/unblob.git external/unblob
        #  # git clone https://github.com/onekey-sec/unblob.git external/unblob
        # fi
        # cd external/unblob || ( echo "Could not install EMBA component unblob" && exit 1 )

        # install unblob with poetry:
        # poetry install --only main
        # UNBLOB_PATH=$(poetry env info --path)

        # Temp solution to install hyperscan in a recent version which is installable on Kali:
        # sed -i 's/hyperscan\ =\ \"0.2.0\"//' pyproject.toml
        # poetry env use "${UNBLOB_PATH}"
        # poetry add hyperscan

        # if [[ -f "${UNBLOB_PATH}""/bin/unblob" ]]; then
        #   export PATH=${PATH}:"${UNBLOB_PATH}""/bin"
        #   echo -e "${GREEN}Identified unblob path: ${ORANGE}${UNBLOB_PATH}${NC}"
        # else
        #   cd "${HOME_PATH}" && ( echo "Could not install EMBA component unblob" && exit 1 )
        # fi

        # cd "${HOME_PATH}" || ( echo "Could not install EMBA component unblob" && exit 1 )

        # echo "${UNBLOB_PATH}" > external/unblob/unblob_path.cfg
        # if [[ -d "${HOME}"/.cache ]] && [[ "${IN_DOCKER}" -eq 1 ]]; then
        #  echo -e "${GREEN}Backup unblob environment for read only docker container: ${ORANGE}${UNBLOB_PATH}${NC}"
        #  cp -pr "${HOME}"/.cache external/unblob/root_cache
        #  rm -rf "${HOME}"/.cache || true
        # fi

        if command -v unblob > /dev/null ; then
          unblob --show-external-dependencies
          echo -e "${GREEN}""unblob installed successfully""${NC}"
          echo
        else
          echo -e "${ORANGE}""unblob installation failed - check it manually""${NC}"
          echo
        fi
      ;;
    esac
  fi
}
