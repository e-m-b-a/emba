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

    print_git_info "trickest cve database" "EMBA-support-repos/trickest-cve" "Trickest CVE to github exploit database"
    print_git_info "cve-search" "EMBA-support-repos/cve-search" "CVE-Search is a tool to import CVE and CPE into a database to facilitate search and processing of CVEs."
    echo -e "$ORANGE""cve-search will be downloaded.""$NC"
    echo -e "$ORANGE""trickest poc database will be downloaded.""$NC"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""trickest, cve-search and mongodb will be downloaded, installed and populated!""$NC"
      ANSWER=("y")
    fi

    if [[ "$LIST_DEP" -ne 1 ]] ; then

      # we always need the cve-search stuff:
      if ! [[ -d external/cve-search ]]; then
        git clone https://github.com/EMBA-support-repos/cve-search.git external/cve-search
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
      else
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
        git pull
      fi

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
        apt-get install -y "$TOOL_NAME" --no-install-recommends
      done < requirements.system

      # this is a temp solution - Currently needed to fulfill broken deps:
      python3 -m pip install -Iv crackmapexec==5.1.7.dev0

      python3 -m pip install -r requirements.txt
      REDIS_PW="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 || true)"

      echo -e "[*] Setting up CVE-search environment - ./external/cve-search/etc/configuration.ini"
      sed -zE 's/localhost([^\n]*\n[^\n]*27017)/172.36.0.1\1/' ./etc/configuration.ini.sample | tee ./etc/configuration.ini &>/dev/null
      # we do not use the web server. In case someone enables it we have a good default configuration in place:
      sed -i "s/^Debug:\ True/Debug:\ False/g" ./etc/configuration.ini
      sed -i "s/^LoginRequired:\ False/LoginRequired:\ True/g" ./etc/configuration.ini

      # if we setup a docker container we do not need to configure the redis passwords
      if [[ $IN_DOCKER -ne 1 ]]; then
        echo -e "[*] Setting password for Redis environment - ./external/cve-search/etc/configuration.ini"
        sed -i "s/^Password:\ .*/Password:\ $REDIS_PW/g" ./etc/configuration.ini

        echo -e "[*] Setting password for Redis environment - /etc/redis/redis.conf"
        sed -i "s/^\#\ requirepass\ .*/requirepass\ $REDIS_PW/g" /etc/redis/redis.conf
        sed -i "s/^requirepass\ .*/requirepass\ $REDIS_PW/g" /etc/redis/redis.conf
      fi
    fi

    case ${ANSWER:0:1} in
      y|Y )

        cd "$HOME_PATH" || ( echo "Could not install EMBA component Trickest" && exit 1 )
        # get trickest repository
        if ! [[ -d external/trickest-cve ]]; then
          git clone https://github.com/EMBA-support-repos/trickest-cve.git external/trickest-cve
        else
          cd external/trickest-cve || ( echo "Could not install EMBA component Trickest" && exit 1 )
          git pull
          cd "$HOME_PATH" || ( echo "Could not install EMBA component Trickest" && exit 1 )
        fi

        CVE_INST=1
        echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed and populated.""$NC"
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
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
          if ! [[ -f /etc/mongod.conf ]]; then
            echo "Could not install EMBA component mongod - missing mongod.conf file" && exit 1
          fi
          sed -i 's/bindIp\:\ 127.0.0.1/bindIp\:\ 172.36.0.1/g' /etc/mongod.conf

          if [[ "$WSL" -eq 0 ]]; then
            systemctl daemon-reload
            systemctl start mongod
            systemctl enable mongod
            systemctl restart mongod.service
          else
            # WSL environment
            mongod --config /etc/mongod.conf &
          fi

          echo -e "\\n""$MAGENTA""$BOLD""The cve-search database will be downloaded and updated!""$NC"
          CVE_INST=1
          echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed and populated.""$NC"
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
          cd "$HOME_PATH" || ( echo "Could not install EMBA component cve-search" && exit 1 )
          sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/emba_updater.init > config/emba_updater
          chmod +x config/emba_updater
          echo -e "\\n""$MAGENTA""$BOLD""The cron.daily update script for EMBA is located in config/emba_updater""$NC"
          echo -e "$MAGENTA""$BOLD""For automatic updates it should be checked and copied to /etc/cron.daily/""$NC"
        fi
        cd "$HOME_PATH" || ( echo "Could not install EMBA component cve-search" && exit 1 )
      ;;
    esac
  fi

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || ( echo "Could not install EMBA component CISA.gov database" && exit 1 )

    # see https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    print_file_info "known_exploited_vulnerabilities.csv" "CISA.gov list of known_exploited_vulnerabilities.csv" "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv" "external/known_exploited_vulnerabilities.csv"

    if [[ "$LIST_DEP" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""These rules (if not already on the system) will be downloaded!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

        download_file "known_exploited_vulnerabilities.csv" "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv" "external/known_exploited_vulnerabilities.csv"

      ;;
    esac
  fi
} 
