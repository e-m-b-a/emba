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

# Description: Installs cve-search for CVE search module in EMBA (F20)

IF20_cve_search() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $CVE_SEARCH -eq 1 ]] || [[ $FULL -eq 1 ]]; then
  
    print_git_info "cve-search" "cve-search/cve-search" "CVE-Search is a tool to import CVE and CPE into a database to facilitate search and processing of CVEs."
    echo -e "$ORANGE""cve-search will be downloaded.""$NC"
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""cve-search and mongodb will be downloaded, installed and populated!""$NC"
      ANSWER=("y")
    fi
  
    if [[ "$LIST_DEP" -ne 1 ]] ; then
      # we always need the cve-search stuff:
      if ! [[ -d external/cve-search ]]; then
        git clone https://github.com/cve-search/cve-search.git external/cve-search
      fi
      cd ./external/cve-search/ || exit 1
  
      while read -r TOOL_NAME; do
        print_tool_info "$TOOL_NAME" 1
      done < requirements.system
  
      while read -r TOOL_NAME; do
        PIP_NAME=$(echo "$TOOL_NAME" | cut -d= -f1)
        TOOL_VERSION=$(echo "$TOOL_NAME" | cut -d= -f3)
        print_pip_info "$PIP_NAME" "$TOOL_VERSION"
      done < requirements.txt
  
      #xargs sudo apt-get install -y < requirements.system
      while read -r TOOL_NAME; do
        apt-get install -y "$TOOL_NAME"
      done < requirements.system
  
      # shellcheck disable=SC2002
      #cat requirements.txt | xargs -n 1 pip install 2>/dev/null
      python3 -m pip install -r requirements.txt
      REDIS_PW="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 || true)"
  
      echo -e "[*] Setting up CVE-search environment - ./external/cve-search/etc/configuration.ini"
      sed -zE 's/localhost([^\n]*\n[^\n]*27017)/172.36.0.1\1/' ./etc/configuration.ini.sample | tee ./etc/configuration.ini &>/dev/null
      # we do not use the web server. In case someone enables it we have a good default configuration in place:
      sed -i "s/^Debug:\ True/Debug:\ False/g" ./etc/configuration.ini
      sed -i "s/^LoginRequired:\ False/LoginRequired:\ True/g" ./etc/configuration.ini

      echo -e "[*] Setting password for Redis environment - ./external/cve-search/etc/configuration.ini"
      sed -i "s/^Password:\ .*/Password:\ $REDIS_PW/g" ./etc/configuration.ini

      echo -e "[*] Setting password for Redis environment - /etc/redis/redis.conf"
      sed -i "s/^\#\ requirepass\ .*/requirepass\ $REDIS_PW/g" /etc/redis/redis.conf
      sed -i "s/^requirepass\ .*/requirepass\ $REDIS_PW/g" /etc/redis/redis.conf
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
  
        CVE_INST=1
        echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed.""$NC"
        cd "$HOME_PATH" || exit 1
        cd ./external/cve-search/ || exit 1
        if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
            CVE_INST=0
            echo -e "\\n""$GREEN""cve-search database already installed - no further action performed.""$NC"
        else
            echo -e "\\n""$MAGENTA""cve-search database not ready.""$NC"
        fi
        if [[ "$CVE_INST" -eq 1 ]]; then
          wget --no-check-certificate -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
          echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
          apt-get update -y
          print_tool_info "mongodb-org" 1
          apt-get install mongodb-org -y
          systemctl daemon-reload
          systemctl start mongod
          systemctl enable mongod
          sed -i 's/bindIp\:\ 127.0.0.1/bindIp\:\ 172.36.0.1/g' /etc/mongod.conf
          systemctl restart mongod.service
  
          echo -e "\\n""$MAGENTA""$BOLD""The cve-search database will be downloaded and updated!""$NC"
          CVE_INST=1
          echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed.""$NC"
          if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
            CVE_INST=0
            echo -e "\\n""$GREEN""cve-search database already installed - no further action performed.""$NC"
          else
            echo -e "\\n""$MAGENTA""cve-search database not ready.""$NC"
            echo -e "\\n""$MAGENTA""The installer is going to populate the database.""$NC"
          fi
          # only update and install the database if we have no working database:
          if [[ "$CVE_INST" -eq 1 ]]; then
            /etc/init.d/redis-server restart
            ./sbin/db_mgmt_cpe_dictionary.py -p || true
            ./sbin/db_mgmt_json.py -p || true
            ./sbin/db_updater.py -f || true
          else
            echo -e "\\n""$GREEN""$BOLD""CVE database is up and running. No installation process performed!""$NC"
          fi
          cd "$HOME_PATH" || exit 1
          sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/emba_updater.init > config/emba_updater
          chmod +x config/emba_updater
          echo -e "\\n""$MAGENTA""$BOLD""The cron.daily update script for EMBA is located in config/emba_updater""$NC"
          echo -e "$MAGENTA""$BOLD""For automatic updates it should be copied to /etc/cron.daily/""$NC"
        fi
        cd "$HOME_PATH" || exit 1
      ;;
    esac
  fi
} 
