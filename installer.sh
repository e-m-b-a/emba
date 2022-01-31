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

export DEBIAN_FRONTEND=noninteractive

export INSTALL_APP_LIST=()
export DOWNLOAD_FILE_LIST=()

export INSTALLER_DIR="./installer"

# force install everything
FORCE=0
# install docker EMBA
IN_DOCKER=0
# list dependencies
LIST_DEP=0

## Color definition
RED="\033[0;31m"
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m"  # no color

## Attribute definition
BOLD="\033[1m"

# shellcheck source=/dev/null
source "$INSTALLER_DIR"/helpers.sh

echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Installer""$NC""\\n""$BOLD""=================================================================""$NC"

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
    c)
      export COMPLEMENT=1
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Complement EMBA dependecies""$NC"
      ;;
    d)
      export DOCKER_SETUP=1
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for EMBA in default/docker mode""$NC"
      ;;
    C)
      export DOCKER_SETUP=0
      export IN_DOCKER=0
      export FULL=0
      export FORCE=1
      export CVE_SEARCH=1
      echo -e "$GREEN""$BOLD""Install CVE-search including the needed database - used for EMBArk installations""$NC"
      ;;
    D)
      export IN_DOCKER=1
      export DOCKER_SETUP=0
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install EMBA in docker image - used for building a docker image""$NC"
      ;;
    F)
      export FORCE=1
      export FULL=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for developer mode""$NC"
      ;;
    h)
      print_help
      exit 0
      ;;
    l)
      export LIST_DEP=1
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

# shellcheck source=/dev/null
source "$INSTALLER_DIR"/I01_default_apps_host.sh

INSTALL_APP_LIST=()

if [[ "$CVE_SEARCH" -ne 1 ]]; then

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I01_default_apps.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I05_emba_docker_image_dl.sh
  
  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I120_cwe_checker.sh
  
  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IP60_fact_extractor.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I13_objdump.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I199_default_tools_github.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I110_yara_check.sh
  
  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I30_version_vulnerability_check.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IF50_aggregator_common.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I20_php_check.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IP18_qnap_decryptor.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IP99_binwalk_default.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IL10_system_emulator.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IL15_emulated_checks_init.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/IP12_avm_freetz_ng_extract.sh

  # shellcheck source=/dev/null
  source "$INSTALLER_DIR"/I108_stacs_password_search.sh
fi

# shellcheck source=/dev/null
source "$INSTALLER_DIR"/I20_cve_search.sh

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
