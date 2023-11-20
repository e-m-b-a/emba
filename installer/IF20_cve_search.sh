#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou, Benedikt Kuehne

# Description: Installs cve-search for CVE search module in EMBA (F20)

IF20_cve_search() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] || [[ "${CVE_SEARCH}" -eq 1 ]] || [[ "${FULL}" -eq 1 ]]; then

    print_git_info "cve-search" "EMBA-support-repos/cve-search" "CVE-Search is a tool to import CVE and CPE into a database to facilitate search and processing of CVEs."
    echo -e "${ORANGE}""cve-search will be downloaded.""${NC}"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""cve-search and mongodb will be downloaded, installed and populated!""${NC}"
      ANSWER=("y")
    fi

    if [[ "${LIST_DEP}" -ne 1 ]] ; then

      # we always need the cve-search stuff:
      if ! [[ -d external/cve-search ]]; then
        git clone https://github.com/EMBA-support-repos/cve-search.git external/cve-search
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
      else
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
        git pull
      fi

      while read -r TOOL_NAME; do
        print_tool_info "${TOOL_NAME}" 1
      done < requirements.system

      # we do not need to install the Flask web environment - we do it manually
      # while read -r TOOL_NAME; do
      #  PIP_NAME=$(echo "${TOOL_NAME}" | cut -d= -f1)
      #  TOOL_VERSION=$(echo "${TOOL_NAME}" | cut -d= -f3)
      #  print_pip_info "${PIP_NAME}" "${TOOL_VERSION}"
      # done < requirements.txt

      # xargs sudo apt-get install -y < requirements.system
      while read -r TOOL_NAME; do
        apt-get install -y "${TOOL_NAME}" --no-install-recommends
      done < requirements.system

      # this is a temp solution - Currently needed to fulfill broken deps:
      # python3 -m pip install -Iv crackmapexec==5.1.7.dev0

      # we do not need to install the Flask web environment - we do it manually
      # python3 -m pip install -r requirements.txt
      pip_install "requests==2.28.1"
      pip_install "Whoosh==2.7.4"
      pip_install "tqdm==4.64.0"
      pip_install "pymongo==3.12.1"
      pip_install "dicttoxml==1.7.4"
      pip_install "redis==4.5.4"
      pip_install "ijson==3.1.4"
      pip_install "jsonpickle==3.0.1"
      pip_install "requirements-parser==0.5.0"
      pip_install "ansicolors==1.1.8"
      pip_install "nltk==3.7"
      pip_install "nested-lookup==0.2.25"
      pip_install "dnspython==2.2.1"
      pip_install "Werkzeug"
      pip_install "python-dateutil"
      pip_install "CveXplore==0.3.17"

      REDIS_PW="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 || true)"

      echo -e "[*] Setting up CVE-search environment - ./external/cve-search/etc/configuration.ini"
      sed -zE "s/localhost([^\n]*\n[^\n]*27017)/${MONGODB_HOST}\1/" ./etc/configuration.ini.sample | tee ./etc/configuration.ini &>/dev/null
      # we do not use the web server. In case someone enables it we have a good default configuration in place:
      sed -i "s/^Debug:\ True/Debug:\ False/g" ./etc/configuration.ini
      sed -i "s/^LoginRequired:\ False/LoginRequired:\ True/g" ./etc/configuration.ini

      # if we setup a docker container we do not need to configure the redis passwords
      if [[ "${IN_DOCKER}" -ne 1 ]]; then
        echo -e "[*] Setting password for Redis environment - ./external/cve-search/etc/configuration.ini"
        sed -i "s/^Password:\ .*/Password:\ ${REDIS_PW}/g" ./etc/configuration.ini

        echo -e "[*] Setting password for Redis environment - /etc/redis/redis.conf"
        sed -i "s/^\#\ requirepass\ .*/requirepass\ ${REDIS_PW}/g" /etc/redis/redis.conf
        sed -i "s/^requirepass\ .*/requirepass\ ${REDIS_PW}/g" /etc/redis/redis.conf
      fi
    fi

    case ${ANSWER:0:1} in
      y|Y )

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )

        CVE_INST=1
        echo -e "\\n""${MAGENTA}""Check if the cve-search database is already installed and populated.""${NC}"
        cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
        if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
          CVE_INST=0
          echo -e "\\n""${GREEN}""cve-search database already installed - no further action performed.""${NC}"
        else
          echo -e "\\n""${MAGENTA}""cve-search database not ready.""${NC}"
        fi

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )
        if [[ "${CVE_INST}" -eq 1 ]]; then
          if ! dpkg -s libssl1.1 &>/dev/null; then
            # libssl1.1 missing
            echo -e "\\n""${BOLD}""Installing libssl1.1 for mongodb!""${NC}"
            # echo "deb http://security.ubuntu.com/ubuntu impish-security main" | tee /etc/apt/sources.list.d/impish-security.list
            for i in {21..29}; do
              echo "Testing download of libssl package version libssl1.1_1.1.1-1ubuntu2.1~18.04.${i}_amd64.deb"
              wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1-1ubuntu2.1~18.04."${i}"_amd64.deb -O external/libssl-dev.deb || true
                # http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1-1ubuntu2.1~18.04.23_amd64.deb
              wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1-1ubuntu2.1~18.04."${i}"_amd64.deb -O external/libssl.deb || true
                # http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1-1ubuntu2.1~18.04.23_amd64.deb
              if [[ "$(file external/libssl.deb)" == *"Debian binary package (format 2.0)"* ]]; then
                break
              else
                [[ -f external/libssl.deb ]] && rm external/libssl.deb
                [[ -f external/libssl-dev.deb ]] && rm external/libssl-dev.deb
              fi
            done

            ! [[ -f external/libssl.deb ]] && ( echo "Could not install libssl" && exit 1)
            ! [[ -f external/libssl-dev.deb ]] && ( echo "Could not install libssl-dev" && exit 1)
            dpkg -i external/libssl.deb
            dpkg -i external/libssl-dev.deb
            [[ -f external/libssl.deb ]] && rm external/libssl.deb
            [[ -f external/libssl-dev.deb ]] && rm external/libssl-dev.deb
          fi

          wget --no-check-certificate -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/mongodb.gpg > /dev/null
          echo "deb [ signed-by=/etc/apt/trusted.gpg.d/mongodb.gpg ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
          apt-get update -y
          print_tool_info "mongodb-org" 1
          apt-get install mongodb-org -y
          if ! [[ -f /etc/mongod.conf ]]; then
            echo "Could not install EMBA component mongod - missing mongod.conf file" && exit 1
          fi
          sed -i "s/bindIp\:\ 127.0.0.1/bindIp\:\ ${MONGODB_HOST}/g" /etc/mongod.conf

          if [[ "${WSL}" -eq 0 ]]; then
            systemctl daemon-reload
            systemctl start mongod
            systemctl enable mongod
            systemctl restart mongod.service
          else
            # WSL environment
            mongod --config /etc/mongod.conf &
          fi

          cd ./external/cve-search/ || ( echo "Could not install EMBA component cve-search" && exit 1 )
          echo -e "\\n""${MAGENTA}""${BOLD}""The cve-search database will be downloaded and updated!""${NC}"
          CVE_INST=1
          echo -e "\\n""${MAGENTA}""Check if the cve-search database is already installed and populated.""${NC}"
          if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
            CVE_INST=0
            echo -e "\\n""${GREEN}""cve-search database already installed - no further action performed.""${NC}"
          else
            echo -e "\\n""${MAGENTA}""cve-search database not ready.""${NC}"
            echo -e "\\n""${MAGENTA}""The installer is going to populate the database.""${NC}"
          fi
          # Find and set Proxy-settings for cvexplore
          if [[ -n "${https_proxy}" ]]; then
            echo -e "\\n""${MAGENTA}""Found a https-proxy settings, will be routing traffic for cvexplore through:""${BOLD}""${https_proxy}""${NC}"
            export HTTP_PROXY_STRING="${https_proxy}"
          fi
          # Find and set NVD_NIST_API_KEY for cvexplore
          if [[ -f "/home/${USER}/.cvexplore/.env" ]]; then
            set -o allexport
            # shellcheck source=/dev/null
            source "/home/${SUDO_USER}/.cvexplore/.env"
            set +o allexport
          fi
          # independently checking if a NIST API key is set
          if [[ -z "${NVD_NIST_API_KEY:-}" ]]; then
            echo -e "\\n""${ORANGE}""${BOLD}""No NVD-NIST API key set. Trying to initialize the database without it""${NC}"
          fi
          # only update and install the database if we have no working database
          # also do not update if we are running as github action (GH_ACTION set to 1)
          if [[ "${GH_ACTION}" -eq 0 ]] && [[ "${CVE_INST}" -eq 1 ]]; then
            /etc/init.d/redis-server restart
            CNT=0
            while [[ "${CVE_INST}" -eq 1 ]]; do
              cvexplore database initialize
              if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
                break
              fi
              if [[ "${CNT}" -gt 4 ]]; then
                break
              fi
              CNT=$((CNT+1))
            done
          else
            echo -e "\\n""${GREEN}""${BOLD}""CVE database is up and running. No installation process performed!""${NC}"
          fi
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )
          sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/emba_updater.init > config/emba_updater
          sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/emba_updater_data.init > config/emba_updater_data
          chmod +x config/emba_updater
          chmod +x config/emba_updater_data
          echo -e "\\n""${MAGENTA}""${BOLD}""The cron.daily update script for EMBA is located in config/emba_updater""${NC}"
          echo -e "${MAGENTA}""${BOLD}""For automatic updates it should be checked and copied to /etc/cron.daily/""${NC}"
        fi
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component cve-search" && exit 1 )
      ;;
    esac
  fi
}
