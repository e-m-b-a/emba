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

# Description:  Installs STACS - https://github.com/stacscan/stacs

I108_stacs_password_search() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()

    cd "${HOME_PATH}" || ( echo "Could not install EMBA component STACS" && exit 1 )

    echo -e "\\nTo find password hashes in firmware files we install STACS and the default rules."

    print_tool_info "python3-pip" 1
    # print_tool_info "libarchive13" 1
    print_tool_info "libarchive-dev" 1
    print_tool_info "pybind11-dev" 1
    print_tool_info "libssl-dev" 1
    # print_pip_info "stacs"
    print_git_info "stacs" "stacscan/stacs" "STACS is a fast, easy to use tool for searching of password hashes in firmware files."
    print_git_info "stacs-rules" "stacscan/stacs-rules" "STACS is a fast, easy to use tool for searching of password hashes in firmware files."

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""STACS and the default rules (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        # if ! [[ -d external/stacs ]]; then
        #   git clone https://github.com/stacscan/stacs.git external/stacs
        # fi

        # cd ./external/stacs || ( echo "Could not install EMBA component STACS" && exit 1 )

        # deactivate python venv for stacs - this is needed to bypass the pydantic dependency clash with semgrep
        # we install stacs in the system and semgrep into the virtual environment
        deactivate
        pip_install "setuptools" "-U"
        pip_install "stacs"
        activate_pipenv "./external/emba_venv"

        # python3 setup.py install
        # cd "${HOME_PATH}" || ( echo "Could not install EMBA component STACS" && exit 1 )

        if ! [[ -d external/stacs-rules ]]; then
          git clone https://github.com/stacscan/stacs-rules.git external/stacs-rules
        fi
        cd ./external/stacs-rules || ( echo "Could not install EMBA component STACS" && exit 1 )
        find rules -name "*.yar" | sed 's/rules\///' \
          | xargs -I{} bash -c "\
            mkdir -p ./tests/fixtures/{}/{positive,negative} ; \
            touch ./tests/fixtures/{}/{negative,positive}/.gitignore" || true
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component STACS" && exit 1 )

        if command -v stacs > /dev/null ; then
          echo -e "${GREEN}""STACS installed successfully""${NC}"
        else
          echo -e "${ORANGE}""STACS installation failed - check it manually""${NC}"
        fi
      ;;
    esac
  fi
}
