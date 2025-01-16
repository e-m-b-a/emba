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

# Description:  Installs multiple tools for code analysis
#               e.g. iniscan for PHP.ini checks

I20_sourcecode_check() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    cd "${HOME_PATH}" || ( echo "Could not install EMBA components for code scanning" && exit 1 )
    INSTALL_APP_LIST=()

    echo -e "\\nTo check the php.ini config for common security practices we have to install Composer and inicheck."

    print_tool_info "shellcheck" 1
    print_tool_info "php" 1
    print_tool_info "luarocks" 1
    # pydantic update needed for semgrep
    print_pip_info "pydantic"
    print_pip_info "semgrep"
    print_git_info "semgrep-rules" "returntocorp/semgrep-rules" "Standard library for Semgrep rules"
    print_git_info "0xdea C/C++ semgrep-rules" "EMBA-support-repos/semgrep-rules-0xdea" "C/C++ Semgrep rules by 0xdea"
    print_git_info "zarn" "EMBA-support-repos/zarn" "Zarn static perl analyzer"
    # cpanminus is needed for zarn:
    print_tool_info "cpanminus" 1

    print_file_info "iniscan/composer.phar" "A Dependency Manager for PHP" "https://getcomposer.org/installer" "external/iniscan/composer.phar"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""Composer, iniscan, luacheck  and semgrep (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        luarocks install luacheck

        pip_install "pydantic" "-U"
        pip_install "semgrep"
        if ! [[ -d external/semgrep-rules ]]; then
          git clone https://github.com/returntocorp/semgrep-rules.git external/semgrep-rules
        fi
        if ! [[ -d external/semgrep-rules-0xdea ]]; then
          git clone https://github.com/EMBA-support-repos/semgrep-rules-0xdea.git external/semgrep-rules-0xdea
        fi

        # zarn perl code analyser
        if ! [[ -d external/zarn ]]; then
          # git clone https://github.com/EMBA-support-repos/zarn.git external/zarn
          git clone https://github.com/htrgouvea/zarn.git external/zarn
          cd external/zarn || ( echo "Could not install EMBA component zarn" && exit 1 )
          # https://github.com/htrgouvea/zarn/issues/3
          git reset --hard 009331c
          cpanm --installdeps .
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component zarn" && exit 1 )
        fi

        if ! [[ -d "external/iniscan" ]] ; then
          mkdir external/iniscan
        fi
        download_file "iniscan/composer.phar" "https://getcomposer.org/installer" "external/iniscan/composer.phar"
        cd ./external/iniscan || ( echo "Could not install EMBA component iniscan" && exit 1 )
        php composer.phar build --no-interaction || true
        php composer.phar global require psecio/iniscan --no-interaction || true
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component iniscan" && exit 1 )
        cp -r "${HOME}""/.config/composer/vendor/" "./external/iniscan/"
      ;;
    esac
  fi
}
