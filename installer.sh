#!/bin/bash -p

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
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs needed stuff for EMBA

# if the installer fails you can try to change it to 0
STRICT_MODE=1

ORIG_USER="${SUDO_USER:-${USER}}"
ORIG_GROUP=$(groups "${ORIG_USER}" | cut -d: -f2 | awk '{print $1}')

export DEBIAN_FRONTEND=noninteractive
export INSTALL_APP_LIST=()
export DOWNLOAD_FILE_LIST=()
export INSTALLER_DIR="./installer"

if [[ "${STRICT_MODE}" -eq 1 ]]; then
  export DEBUG_SCRIPT=0
  if [[ -f "./helpers/helpers_emba_load_strict_settings.sh" ]]; then
    # shellcheck source=/dev/null
    source ./helpers/helpers_emba_load_strict_settings.sh
  elif [[ -f "/installer/helpers_emba_load_strict_settings.sh" ]]; then
    # in docker this is in /emba/...
    # shellcheck source=/dev/null
    source /installer/helpers_emba_load_strict_settings.sh
  else
    echo "Warning - strict mode module not found"
  fi
  load_strict_mode_settings
  trap 'wickStrictModeFail $? | tee -a /tmp/emba_installer.log' ERR  # The ERR trap is triggered when a script catches an error
fi

# install docker EMBA
export IN_DOCKER=0
# list dependencies
export LIST_DEP=0
export FULL=0
export REMOVE=0
# other os stuff
export OTHER_OS=0
export UBUNTU_OS=0
export WSL=0
export GH_ACTION=0
export SSL_REPOS=0

## Color definition
export RED="\033[0;31m"
export GREEN="\033[0;32m"
export ORANGE="\033[0;33m"
export MAGENTA="\033[0;35m"
export CYAN="\033[0;36m"
export BLUE="\033[0;34m"
export NC="\033[0m"  # no color

## Attribute definition
export BOLD="\033[1m"

echo -e "\\n""${ORANGE}""${BOLD}""EMBA - Embedded Linux Analyzer Installer""${NC}"
echo -e "${BOLD}""=================================================================""${NC}"

# import all the installation modules
mapfile -t INSTALLERS < <(find "${INSTALLER_DIR}" -iname "*.sh" 2> /dev/null)
INSTALLER_COUNT=0
for INSTALLER_FILE in "${INSTALLERS[@]}" ; do
  # https://github.com/koalaman/shellcheck/wiki/SC1090
  # shellcheck source=/dev/null
  source "${INSTALLER_FILE}"
  (( INSTALLER_COUNT+=1 ))
done

echo ""
echo -e "==> ""${GREEN}""Imported ""${INSTALLER_COUNT}"" installer module files""${NC}"
echo ""

if [[ "$#" -lt 1 ]] || [[ "$#" -gt 2 ]]; then
  echo -e "${RED}""${BOLD}""Invalid number of arguments""${NC}"
  echo -e "\n\n------------------------------------------------------------------"
  echo -e "If you are going to install EMBA in default mode you can use:"
  echo -e "${CYAN}""     sudo ./installer.sh -d""${NC}"
  echo -e "------------------------------------------------------------------\n\n"
  print_help
  exit 1
fi

while getopts CdDFghlrsc: OPT ; do
  case ${OPT} in
    d)
      export DOCKER_SETUP=1
      export CVE_SEARCH=0
      echo -e "${GREEN}""${BOLD}""Install all dependencies for EMBA in default/docker mode""${NC}"
      ;;
    D)
      export IN_DOCKER=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=0
      echo -e "${GREEN}""${BOLD}""Install EMBA in docker image - used for building a docker image""${NC}"
      ;;
    F)
      export FULL=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=1
      echo -e "${GREEN}""${BOLD}""Install all dependecies for developer mode""${NC}"
      ;;
    g)
      export DOCKER_SETUP=1
      export GH_ACTION=1
      export CVE_SEARCH=0
      echo -e "${GREEN}""${BOLD}""Install all dependecies for EMBA test via Github actions""${NC}"
      echo -e "${GREEN}""${BOLD}""This mode is a default installation without populating the CVE-search database""${NC}"
      ;;
    h)
      print_help
      exit 0
      ;;
    l)
      export LIST_DEP=1
      export CVE_SEARCH=0
      export DOCKER_SETUP=0
      echo -e "${GREEN}""${BOLD}""List all dependecies (Warning: deprecated feature)""${NC}"
      ;;
    r)
      export REMOVE=1
      echo -e "${GREEN}""${BOLD}""Remove EMBA from the system""${NC}"
      ;;
    s)
      export SSL_REPOS=1
      echo -e "${GREEN}""${BOLD}""HTTPS repos are used for installation""${NC}"
      ;;
    c)
      export CONTAINER="${OPTARG}"
      ;;
    *)
      echo -e "${RED}""${BOLD}""Invalid option""${NC}"
      print_help
      exit 1
      ;;
  esac
done

if ! [[ -v CONTAINER ]]; then
  if [[ -f docker-compose.yml ]]; then
    CONTAINER="$(grep image docker-compose.yml | awk '{print $2}' | sort -u)"
  else
    CONTAINER="embeddedanalyzer/emba"
  fi
fi

if [[ "${LIST_DEP}" -eq 1 ]]; then
  echo -e "\n${ORANGE}WARNING: This feature is deprecated and not maintained anymore.${NC}"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
fi

# WSL support - currently experimental!
if grep -q -i wsl /proc/version; then
  echo -e "\n${ORANGE}INFO: System running in WSL environment!${NC}"
  echo -e "\n${ORANGE}INFO: WSL is currently experimental!${NC}"
  echo -e "\n${ORANGE}Please check the documentation https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites${NC}"
  echo -e "\n${ORANGE}WARNING: If you are using WSL2, disable docker integration from the docker-desktop daemon!${NC}"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  WSL=1
fi

# distribution check
if ! grep -Eq "ID(_LIKE)?=(\")?(ubuntu)?( )?(debian)?" /etc/os-release 2>/dev/null ; then
  echo -e "\\n""${RED}""EMBA only supports debian based distributions!""${NC}\\n"
  print_help
  exit 1
elif ! grep -q "kali" /etc/debian_version 2>/dev/null ; then
  if grep -q "VERSION_ID=\"22.04\"\|VERSION_ID=\"24.04\"" /etc/os-release 2>/dev/null ; then
    # How to handle sub-versioning ? if grep -q -E "PRETTY_NAME=\"Ubuntu\ 22\.04(\.[0-9]+)?\ LTS\"" /etc/os-release 2>/dev/null ; then
    OTHER_OS=1
    UBUNTU_OS=1
  elif grep -q "PRETTY_NAME=\"Ubuntu 20.04 LTS\"" /etc/os-release 2>/dev/null ; then
    echo -e "\\n""${RED}""EMBA is not fully supported on Ubuntu 20.04 LTS.""${NC}"
    echo -e "${RED}""For EMBA installation you need to update docker-compose manually. See also https://github.com/e-m-b-a/emba/issues/247""${NC}"
    echo -e "\\n""${ORANGE}""Please check the documentation https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites""${NC}"
    read -p "If you have updated docker-compose you can press any key to continue ..." -n1 -s -r
    OTHER_OS=0  # installation procedure identical to kali install
    UBUNTU_OS=0 # installation procedure identical to kali install
  else
    echo -e "\n${ORANGE}WARNING: compatibility of distribution/version unknown!${NC}"
    OTHER_OS=1
    read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  fi
else
  OTHER_OS=0
  UBUNTU_OS=0
fi

if ! uname -m | grep -q "x86_64" 2>/dev/null; then
  echo -e "\n${ORANGE}WARNING: Architecture probably unsupported!${NC}"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
fi

if ! grep -q "ssse3" /proc/cpuinfo 2>/dev/null; then
  echo -e "\n${ORANGE}WARNING: CPU type and feature set probably unsupported - Missing SSSE3 support detected!${NC}"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
fi

if ! [[ ${EUID} -eq 0 ]] && [[ ${LIST_DEP} -eq 0 ]] ; then
  echo -e "\\n""${RED}""Run EMBA installation script with root permissions!""${NC}\\n"
  print_help
  exit 1
fi

# standard stuff before installation run

HOME_PATH=$(pwd)

if [[ "${REMOVE}" -eq 1 ]]; then
  R00_emba_remove
  exit 0
fi

# quick check if we have enough disk space for the docker image

if [[ "${IN_DOCKER}" -eq 0 ]]; then
  if [[ -d "/var/lib/docker/" ]]; then
    # docker is already installed
    DDISK="/var/lib/docker"
  else
    # default
    DDISK="/var/lib/"
  fi

  FREE_SPACE=$(df --output=avail "${DDISK}" | awk 'NR==2')
  if [[ "${FREE_SPACE}" -lt 19000000 ]]; then
    echo -e "\\n""${ORANGE}""EMBA installation in default mode needs a minimum of 18Gig for the docker image""${NC}"
    echo -e "\\n""${ORANGE}""Please free enough space on /var/lib/docker""${NC}"
    echo -e "\\n""${ORANGE}""Please check the documentation https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites""${NC}"
    echo ""
    df -h || true
    echo ""
    read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  fi

  TOTAL_MEMORY="$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
  if [[ "${TOTAL_MEMORY}" -lt 4000000 ]]; then
    echo -e "\\n""${ORANGE}""EMBA installation in default mode needs a minimum of 4Gig of RAM""${NC}"
    echo -e "\\n""${ORANGE}""Please check the documentation https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites""${NC}"
    echo ""
    read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  fi
fi

if [[ ${LIST_DEP} -eq 0 ]] ; then
  if ! [[ -d "external" ]] ; then
    echo -e "\\n""${ORANGE}""Created external directory: ./external""${NC}"
    mkdir external
    # currently this is needed for full install on Ubuntu
    # the freetz installation is running as freetzuser and needs write access:
    chown "${ORIG_USER}":"${ORIG_GROUP}" ./external
    chmod 777 ./external
  else
    echo -e "\\n""${ORANGE}""WARNING: external directory available: ./external""${NC}"
    echo -e "${ORANGE}""Please remove it before proceeding ...""${NC}"
    echo ""
    read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  fi

  echo -e "\\n""${ORANGE}""Update package lists.""${NC}"
  if [[ "${SSL_REPOS}" -eq 1 ]]; then
    sed -i 's/deb http:\/\//deb https:\/\//g' /etc/apt/sources.list
    sed -i 's/deb-src http:\/\//deb-src https:\/\//g' /etc/apt/sources.list
  fi
  apt-get -y update
fi

# setup the python virtual environment in external directory
# external is also setup in the docker image
apt-get -y install python3-venv
create_pipenv "./external/emba_venv"
activate_pipenv "./external/emba_venv"

if ! command -v docker > /dev/null || ! command -v docker compose > /dev/null ; then
  # OS debian is for Kali Linux
  OS="debian"
  [[ "${UBUNTU_OS}" -eq 1 ]] && OS="ubuntu"
  # Add Docker's official GPG key:
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/"${OS}"/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  # Add the repository to Apt sources:
  if [[ "${UBUNTU_OS}" -eq 1 ]]; then
    # shellcheck source=/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${OS} \
    $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  else
    # probably a kali linux
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${OS} \
    bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  fi
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  export DOCKER_COMPOSE=("docker" "compose")
elif command -v docker-compose > /dev/null ; then
  echo -e "\n${ORANGE}""${BOLD}""WARNING: Old docker-compose installation found""${NC}"
  echo -e "${ORANGE}""${BOLD}""It is recommend to remove the current docker installation and restart the EMBA installation afterwards!""${NC}"
  echo -e "${ORANGE}Please check the installed docker packages the following way: dpkg -l | grep docker.${NC}"
  echo -e "${ORANGE}Afterwards it can be cleaned up via apt-get the following way:${NC}"
  echo -e "${ORANGE}$ sudo apt-get remove docker docker-compose docker.io python3-docker${NC}"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
  export DOCKER_COMPOSE=("docker-compose")
  # if we do not have the docker command it probably is a more modern system and we need to install the docker-cli package
  if ! command -v docker > /dev/null; then
    echo -e "\n${ORANGE}WARNING: No docker command available -> we check for docker-cli package${NC}"
    if [[ "$(apt-cache search docker-cli | wc -l)" -gt 0 ]]; then
      echo -e "\n${ORANGE}Info: No docker command available -> we install the docker-cli package now${NC}"
      apt-get install docker-cli -y
    fi
  fi
fi

# docker moved around v7 to a new API (API v2)
# we need to check if our installed docker version has support for the compose sub-command:
if command -v docker > /dev/null; then
  if docker --help | grep -q compose; then
    # new docker API version v2 -> docker v7
    export DOCKER_COMPOSE=("docker" "compose")
  elif command -v docker-compose > /dev/null; then
    # we only need to check the docker-compose version if we are running on the old API with docker-compose
    DOCKER_COMP_VER=$("${DOCKER_COMPOSE[@]}" -v | grep version | tr '-' ' ' | awk '{print $4}' | tr -d ',' | sed 's/^v//')
    if [[ $(version "${DOCKER_COMP_VER}") -lt $(version "1.28.5") ]]; then
      echo -e "\n${ORANGE}WARNING: compatibility of the used docker-compose version is unknown!${NC}"
      echo -e "\n${ORANGE}Please consider updating your docker-compose installation to version 1.28.5 or later.${NC}"
      echo -e "\n${ORANGE}Please check the EMBA wiki for further details: https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites${NC}"
      read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
    fi
  fi
fi

# if DOCKER_COMPOSE is not set we are in trouble
if ! [[ -v DOCKER_COMPOSE[@] ]]; then
  echo -e "\n${ORANGE}""${BOLD}""WARNING: No docker installation performed""${NC}"
  echo -e "${ORANGE}If you are running into installation issues please check your docker installation${NC}"
  echo -e "${ORANGE}and ensure the docker and docker compose command are available in your system path.${NC}"
  echo ""
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
fi

# initial installation of the host environment:
I01_default_apps_host

if [[ "${OTHER_OS}" -eq 1 ]]; then
  # UBUNTU
  if [[ "${UBUNTU_OS}" -eq 1 ]]; then
    ID1_ubuntu_os
  fi
fi

INSTALL_APP_LIST=()

if [[ "${WSL}" -eq 1 ]]; then
  echo "[*] Starting dockerd manually in wsl environments:"
  dockerd --iptables=false &
  sleep 3
  reset
fi

if [[ "${CVE_SEARCH}" -ne 1 ]] || [[ "${DOCKER_SETUP}" -ne 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]]; then

  I01_default_apps

  I13_disasm

  I05_emba_docker_image_dl

  IP00_extractors

  IP35_uefi_extraction

  IP61_unblob

  IP99_binwalk_default

  I02_UEFI_fwhunt

  I17_apk_check

  I20_sourcecode_check

  I24_25_kernel_tools

  I108_stacs_password_search

  I110_yara_check

  I199_default_tools_github

  I120_cwe_checker

  IL10_system_emulator

  IL15_emulated_checks_init

  IF17_cve_bin_tool

  IF50_aggregator_common
fi

if [[ "${IN_DOCKER}" -ne 1 ]]; then
  # NVD CVE data feed is always installed on the host:
  IF20_nvd_feed
fi

deactivate

cd "${HOME_PATH}" || exit 1

# we reset the permissions of external from 777 back to 755:
chmod 755 ./external

if [[ "${LIST_DEP}" -eq 0 ]] || [[ ${IN_DOCKER} -eq 0 ]] || [[ ${DOCKER_SETUP} -eq 1 ]] || [[ ${FULL} -eq 1 ]]; then
  echo -e "\\n""${MAGENTA}""${BOLD}""Installation notes:""${NC}"
  echo -e "\\n""${MAGENTA}""WARNING: If you plan using the emulator (-E switch) your host and your internal network needs to be protected.""${NC}"
  echo -e "\\n""${MAGENTA}""INFO: Do not forget to checkout current development of EMBA at https://github.com/e-m-b-a.""${NC}"
fi
if [[ "${WSL}" -eq 1 ]]; then
  echo -e "\\n""${MAGENTA}""INFO: In the current WSL installation the docker and mongod services started manually!""${NC}"
fi

if [[ "${LIST_DEP}" -eq 0 ]]; then
  echo -e "${GREEN}""EMBA installation finished ""${NC}"
fi
