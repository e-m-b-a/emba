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

# Description:  Installs needed stuff for EMBA

# it the installer fails you can try to change it to 0
STRICT_MODE=1

export DEBIAN_FRONTEND=noninteractive
export INSTALL_APP_LIST=()
export DOWNLOAD_FILE_LIST=()
export INSTALLER_DIR="./installer"

if [[ "$STRICT_MODE" -eq 1 ]]; then
  # http://redsymbol.net/articles/unofficial-bash-strict-mode/
  # https://github.com/tests-always-included/wick/blob/master/doc/bash-strict-mode.md
  set -e          # Exit immediately if a command exits with a non-zero status
  set -u          # Exit and trigger the ERR trap when accessing an unset variable
  set -o pipefail # The return value of a pipeline is the value of the last (rightmost) command to exit with a non-zero status
  set -E          # The ERR trap is inherited by shell functions, command substitutions and commands in subshells
  shopt -s extdebug # Enable extended debugging
  IFS=$'\n\t'     # Set the "internal field separator"
  trap 'wickStrictModeFail $? | tee -a /tmp/emba_installer.log' ERR  # The ERR trap is triggered when a script catches an error
fi

# install docker EMBA
export IN_DOCKER=0
# list dependencies
export LIST_DEP=0
export FULL=0
# other os stuff
export OTHER_OS=0

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

echo -e "\\n""$ORANGE""$BOLD""EMBA - Embedded Linux Analyzer Installer""$NC""\\n""$BOLD""=================================================================""$NC"

# import all the installation modules
mapfile -t INSTALLERS < <(find "$INSTALLER_DIR" -iname "*.sh" 2> /dev/null)
INSTALLER_COUNT=0
for INSTALLER_FILE in "${INSTALLERS[@]}" ; do
  # https://github.com/koalaman/shellcheck/wiki/SC1090
  # shellcheck source=/dev/null
  source "$INSTALLER_FILE"
  (( INSTALLER_COUNT+=1 ))
done

echo ""
echo -e "==> ""$GREEN""Imported ""$INSTALLER_COUNT"" installer module files""$NC"
echo ""

if [ "$#" -ne 1 ]; then
  echo -e "$RED""$BOLD""Invalid number of arguments""$NC"
  echo -e "\n\n------------------------------------------------------------------"
  echo -e "Probably you would check all packets we are going to install with:"
  echo -e "$CYAN""     sudo ./installer.sh -l""$NC"
  echo -e "If you are going to install EMBA in default mode you can use:"
  echo -e "$CYAN""     sudo ./installer.sh -d""$NC"
  echo -e "------------------------------------------------------------------\n\n"
  print_help
  exit 1
fi

while getopts cCdDFhl OPT ; do
  case $OPT in
    d)
      export DOCKER_SETUP=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for EMBA in default/docker mode""$NC"
      ;;
    D)
      export IN_DOCKER=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install EMBA in docker image - used for building a docker image""$NC"
      ;;
    F)
      export FULL=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=1
      echo -e "$GREEN""$BOLD""Install all dependecies for developer mode""$NC"
      ;;
    c)
      export OTHER_OS=1
      export DOCKER_SETUP=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for custom os in docker-mode""$NC"
      ;;
    h)
      print_help
      exit 0
      ;;
    l)
      export LIST_DEP=1
      export CVE_SEARCH=0
      export DOCKER_SETUP=0
      echo -e "$GREEN""$BOLD""List all dependecies""$NC"
      ;;
    *)
      echo -e "$RED""$BOLD""Invalid option""$NC"
      print_help
      exit 1
      ;;
  esac
done

if ! [[ $EUID -eq 0 ]] && [[ $LIST_DEP -eq 0 ]] ; then
  echo -e "\\n""$RED""Run EMBA installation script with root permissions!""$NC\\n"
  print_help
  exit 1
fi

# standard stuff before installation run

HOME_PATH=$(pwd)

if [[ $LIST_DEP -eq 0 ]] ; then
  if ! [[ -d "external" ]] ; then
    echo -e "\\n""$ORANGE""Created external directory: ./external""$NC"
    mkdir external
  fi

  echo -e "\\n""$ORANGE""Update package lists.""$NC"
  apt-get -y update
fi


# initial installation of the host environment:
I01_default_apps_host

DOCKER_COMP_VER=$(docker-compose -v | grep version | awk '{print $3}' | tr -d ',')
if [[ $(version "$DOCKER_COMP_VER") -lt $(version "1.28.5") ]]; then
  echo -e "\n${ORANGE}WARNING: compatibility of the used docker-compose version is unknown!$NC"
  echo -e "\n${ORANGE}Please consider updating your docker-compose installation to version 1.28.5 or later.$NC"
  echo -e "\n${ORANGE}Please check the EMBA wiki for further details: https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites$NC"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r
fi

if [[ "$OTHER_OS" -eq 1 ]]; then
  I02_custom_os
fi

INSTALL_APP_LIST=()

if [[ "$CVE_SEARCH" -ne 1 ]] || [[ "$DOCKER_SETUP" -ne 1 ]] || [[ "$IN_DOCKER" -eq 1 ]]; then

  I01_default_apps

  I05_emba_docker_image_dl

  IP00_extractors

  IP12_avm_freetz_ng_extract

  IP18_qnap_decryptor

  IP99_binwalk_default

  I13_objdump

  I20_php_check

  I108_stacs_password_search

  I110_yara_check

  I199_default_tools_github

  I120_cwe_checker

  IL10_system_emulator

  IL15_emulated_checks_init

  IF50_aggregator_common

fi

# cve-search is always installed on the host:
IF20_cve_search

cd "$HOME_PATH" || exit 1

if [[ "$LIST_DEP" -eq 0 ]] || [[ $IN_DOCKER -eq 0 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $FULL -eq 1 ]]; then
  echo -e "\\n""$MAGENTA""$BOLD""Installation notes:""$NC"
  echo -e "\\n""$MAGENTA""INFO: The cron.daily update script for EMBA is located in config/emba_updater""$NC"
  echo -e "$MAGENTA""INFO: For automatic updates it should be copied to /etc/cron.daily/""$NC"
  echo -e "$MAGENTA""INFO: For manual updates just start it via sudo ./config/emba_updater""$NC"

  echo -e "\\n""$MAGENTA""WARNING: If you plan using the emulator (-E switch) your host and your internal network needs to be protected.""$NC"

  echo -e "\\n""$MAGENTA""INFO: Do not forget to checkout current development of EMBA at https://github.com/e-m-b-a.""$NC"
fi

if [[ "$LIST_DEP" -eq 0 ]]; then
  echo -e "$GREEN""EMBA installation finished ""$NC"
fi
