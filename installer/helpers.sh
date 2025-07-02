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

# Description:  Helpers for EMBA installation

print_help()
{
  echo -e "\\n""${CYAN}""USAGE""${NC}"
  echo -e "${CYAN}""-d""${NC}""         Default installation of all dependencies needed for EMBA in default/docker mode (typical initial installation)"
  echo -e "${CYAN}""-D""${NC}""         Only used via docker-compose for building EMBA docker container"
  echo -e "${CYAN}""-F""${NC}""         Developer installation (for running on your host in developer mode)"
  echo -e "${CYAN}""-g""${NC}""         Install all dependencies for EMBA tests via Github actions (CVE-search database not populated)""${NC}"
  echo -e "${CYAN}""-h""${NC}""         Print this help message"
  echo -e "${CYAN}""-l""${NC}""         List all dependencies of EMBA (deprecated)"
  echo -e "${CYAN}""-r""${NC}""         Remove a default installation of EMBA"
  echo -e "${CYAN}""-s""${NC}""         Switch to HTTPS repositories"
  echo -e "${CYAN}""-c {x}""${NC}""     Choose docker image to install (replace {x} with the name)"
  echo
}

module_title()
{
  local MODULE_TITLE
  MODULE_TITLE="${1:-}"
  local MODULE_TITLE_FORMAT
  MODULE_TITLE_FORMAT="[""${BLUE}""+""${NC}""] ""${CYAN}""${BOLD}""${MODULE_TITLE}""${NC}""\\n""${BOLD}""=================================================================""${NC}"
  echo -e "\\n\\n""${MODULE_TITLE_FORMAT}"
}

# print_tool_info a b c
# a = application name (by apt)
# b = no update, if already installed -> 0
#     update, if already installed -> 1
# c = if given: check if this application is on the system instead of a

print_tool_info(){
  echo -e "\\n""${ORANGE}""${BOLD}""${1:-}""${NC}"
  TOOL_INFO="$(apt show "${1:-}" 2> /dev/null)"
  if echo "${TOOL_INFO}" | grep -q "Description:" 2>/dev/null ; then
    echo -e "$(echo "${TOOL_INFO}" | grep "Description:")"
    SIZE=$(apt show "${1:-}" 2>/dev/null | grep Download-Size | cut -d: -f2 || true)
    if [[ -n "${SIZE}" ]]; then
      echo -e "Download-Size:${SIZE}"
    fi
    if echo "${TOOL_INFO}" | grep -E "^E:\ "; then
      echo -e "${RED}""${1:-}"" was not identified and is not installable.""${NC}"
    else
      COMMAND_=""
      if [[ -n ${3+x} ]] ; then
        COMMAND_="${3:-}"
      else
        COMMAND_="${1:-}"
      fi
      if ( command -v "${COMMAND_}" > /dev/null) || ( dpkg -s "${1}" 2> /dev/null | grep -q "Status: install ok installed" ) ; then
        UPDATE=$(LANG=en apt-cache policy "${1}" | grep -i install | cut -d: -f2 | tr -d "^[:blank:]" | uniq | wc -l)
        if [[ "${UPDATE}" -eq 1 ]] ; then
          echo -e "${GREEN}""${1:-}"" won't be updated.""${NC}"
        else
          echo -e "${ORANGE}""${1:-}"" will be updated.""${NC}"
          INSTALL_APP_LIST+=("${1:-}")
        fi
      else
        echo -e "${ORANGE}""${1:-}"" will be newly installed.""${NC}"
        INSTALL_APP_LIST+=("${1:-}")
      fi
    fi
  else
    echo -e "${RED}""${1:-}"" is not available anymore - installation can't proceed.""${NC}"
    exit 1
  fi
}

# print_git_info a b c
# a = tool name
# b = GIT url
# c = description of tool

print_git_info() {
  local GIT_NAME="${1:-}"
  local GIT_URL="${2:-}"
  local GIT_DESC="${3:-}"
  local GIT_SIZE=0

  echo -e "\\n""${ORANGE}""${BOLD}""${GIT_NAME}""${NC}"
  if [[ -n "${GIT_DESC}" ]] ; then
    echo -e "Description: ""${GIT_DESC}"
  fi

  if command -v jq >/dev/null ; then
    GIT_SIZE=$(curl https://api.github.com/repos/"${GIT_URL}" 2> /dev/null | jq -r '.size' || true)

    if [[ -n "${GIT_SIZE+0}" ]] && [[ "${GIT_SIZE}" =~ [0-9]+ ]]; then
      if (( GIT_SIZE > 1024 )) ; then
        echo -e "Download-Size: ""$(( GIT_SIZE / 1024 ))"" MB"
      else
        echo -e "Download-Size: ""${GIT_SIZE}"" KB"
      fi
    fi
  fi
}

# print_pip_info a b
# a = file name
# b = package version

print_pip_info() {
  local PIP_NAME="${1:-}"
  local INSTALLED=0
  if [[ -n "${2+x}" ]] ; then
    local PACKAGE_VERSION="${2:-}"
  fi
  echo -e "\\n""${ORANGE}""${BOLD}""${PIP_NAME}""${NC}"
  mapfile -t PIP_INFOS < <(pip3 show "${PIP_NAME}" 2>/dev/null || true)
  # in the error message of pip install we can find all available versions
  if [[ -n "${PACKAGE_VERSION+x}" ]] ; then
    PVERSION=$(pip3 install "${PIP_NAME}==" 2>&1 | grep -o "${PACKAGE_VERSION}" || true)
  else
  #  PVERSION=$(pip3 install "${PIP_NAME}" 2>&1 | grep -v "Requirement already satisfied")
    PVERSION="NA"
  fi
  for INFO in "${PIP_INFOS[@]}"; do
    if [[ "${INFO}" == *"WARNING: "* ]]; then
      continue
    fi
    if [[ "${INFO}" == *"Summary"* ]]; then
      INFO=${INFO//Summary/Description}
      if [[ -n "${PVERSION}" ]]; then
        echo -e "${INFO} / Version: ${PVERSION}"
      elif [[ -n "${VERSION}" ]]; then
        echo -e "${INFO} ${VERSION}"
      else
        echo -e "${INFO}"
      fi
    fi
    if [[ "${INFO}" == *"Version"* ]]; then
      VERSION=" / ""${INFO}"
    fi
  done

  # we need grep -c -> with -q we got errors
  if [[ -n "${PACKAGE_VERSION+x}" ]]; then
    INSTALLED=$(pip3 list 2>/dev/null | grep -E -c "^${PIP_NAME}[[:space:]]+${PACKAGE_VERSION}" || true)
  fi
  if [[ "${INSTALLED}" -gt 0 ]]; then
    echo -e "${GREEN}""${PIP_NAME}"" is already installed - no further action performed.""${NC}"
  else
    INSTALLED=$(pip3 list 2>/dev/null | grep -E -c "^${PIP_NAME}" || true)
    if [[ "${INSTALLED}" -gt 0 ]]; then
      echo -e "${ORANGE}""${PIP_NAME}"" is already installed and will be updated (if a newer version is available).""${NC}"
    else
      echo -e "${ORANGE}""${PIP_NAME}"" will be installed.""${NC}"
    fi
  fi
}

pip_install() {
  local PIP_NAME="${1:-}"
  local PIP_PARAMS=("${PIP_NAME}")
  local PIP_OPTS="${2:-}"
  if [[ -n "${PIP_OPTS}" ]]; then
    PIP_PARAMS+=("${PIP_OPTS}")
  fi

  local PIP_VERS=""
  PIP_VERS=$(pip3 -V | awk '{print $2}')
  if [[ "$(version "${PIP_VERS}")" -ge "$(version "23")" ]]; then
    PIP_PARAMS+=(--break-system-packages)
  fi
  pip3 install "${PIP_PARAMS[@]}"
}

# print_file_info a b c d e
# a = file name
# b = description of file
# c = file url
# d = path on system
# e = if given: check this path or application is on the system instead of d

print_file_info()
{
  local CONTENT_LENGTH=""
  local FILE_SIZE=0
  echo -e "\\n""${ORANGE}""${BOLD}""${1:-}""${NC}"
  if [[ -n "${2:-}" ]] ; then
    echo -e "Description: ""${2:-}"
  fi
  # echo "$(wget "${3}" --spider --server-response -O -)"
  CONTENT_LENGTH=$(wget "${3:-}" --no-check-certificate --spider --server-response --output-file=./.wget.log 2>&1 | sed -ne '/.ontent-.ength/{s/.*: //;p}' | sed '$!d' || true)
  if [[ -n "${CONTENT_LENGTH}" ]]; then
    FILE_SIZE=$(("${CONTENT_LENGTH}"))
  else
    # try grep from .wget.log
    FILE_SIZE=$(("$(sed -ne '/.ontent-.ength/{s/.*: //;p}' ./.wget.log | sed '$!d')"))
  fi

  if (( FILE_SIZE > 1048576 )) ; then
    echo -e "Download-Size: ""$(( FILE_SIZE / 1048576 ))"" MB"
  elif (( FILE_SIZE > 1024 )) ; then
    echo -e "Download-Size: ""$(( FILE_SIZE / 1024 ))"" KB"
  else
    echo -e "Download-Size: ""${FILE_SIZE}"" B"
  fi

  if ! [[ -f "${4:-}" ]] ; then
    if [[ -n "${5+x}" ]] ; then
      if [[ -f "${5:-}" ]] || ( command -v "${5:-}" > /dev/null) || ( dpkg -s "${5:-}" 2> /dev/null | grep -q "Status: install ok installed" ) ; then
        echo -e "${GREEN}""${1:-}"" is already installed - no further action performed.""${NC}"
      else
        echo -e "${ORANGE}""${1:-}"" will be downloaded.""${NC}"
        DOWNLOAD_FILE_LIST+=("${1:-}")
      fi
    else
      echo -e "${ORANGE}""${1:-}"" will be downloaded.""${NC}"
      DOWNLOAD_FILE_LIST+=("${1:-}")
    fi
  else
    echo -e "${ORANGE}""${1:-}"" has already been downloaded.""${NC}"
  fi
  if [[ -f "./.wget.log" ]]; then
    rm "./.wget.log" || true
  fi
}

# download_file a b c
# a = file name
# b = file url
# c = path on system
# WARNING: you need to do a print_file_info first!

download_file()
{
  for D_FILE in "${DOWNLOAD_FILE_LIST[@]}" ; do
    if [[ "${D_FILE}" == "${1:-}" ]] ; then
      echo -e "\\n""${ORANGE}""${BOLD}""Downloading ""${1:-}""${NC}"
      if ! [[ -f "${3:-}" ]] ; then
        wget --no-check-certificate --output-file=./.wget.log "${2:-}" -O "${3:-}"
        if [[ -f "./.wget.log" ]]; then
          cat ./.wget.log
        fi
      else
        echo -e "${GREEN}""${1}"" is already downloaded - no further action performed.""${NC}"
      fi
    fi
  done
  if [[ -f "${3:-}" ]] && ! [[ -x "${3:-}" ]] ; then
    chmod +x "${3:-}"
  fi
  if [[ -f "./.wget.log" ]]; then
    rm "./.wget.log" || true
  fi
}

# Source: https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
version() { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

create_pipenv() {
  local PENV="${1}"
  echo -e "\\n""${ORANGE}""${BOLD}""Creating Python Environment - ${PENV}""${NC}"
  python3 -m venv "${PENV}"
}

activate_pipenv() {
  local PENV="${1}"
  echo -e "\\n""${ORANGE}""${BOLD}""Activating Python Environment - ${PENV}""${NC}"
  # shellcheck source=/dev/null
  source "${PENV}"/bin/activate
}
