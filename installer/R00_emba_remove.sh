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

# Description:  Removes a default EMBA installation from the system

R00_emba_remove() {
  echo -e "\\n""${RED}""A default installation of EMBA will be removed from this system. This includes the following steps:""${NC}"
  echo -e "\\n""${ORANGE}""Stopping EMBA processes""${NC}"
  echo -e "${ORANGE}""Stopping mongod and redis server""${NC}"
  echo -e "${ORANGE}""Removing mongod (purge) and configuration""${NC}"
  echo -e "${ORANGE}""Removing mongod apt configuration""${NC}"
  echo -e "${ORANGE}""Removing redis-server (purge) and configuration""${NC}"
  echo -e "${ORANGE}""Removing EMBA docker images""${NC}"
  echo -e "${ORANGE}""Removing external directory: ./external""${NC}\\n"
  read -p "If you know what you are doing you can press any key to continue ..." -n1 -s -r

  echo -e "\\n""${ORANGE}""Stopping EMBA processes""${NC}"
  pkill -f "emba" || true

  echo -e "\\n""${ORANGE}""Stopping mongod process""${NC}"
  if [[ -f "/etc/init.d/mongod" ]]; then
    /etc/init.d/mongod stop
  else
    systemctl stop mongod
  fi
  echo -e "\\n""${ORANGE}""Stopping redis-server process""${NC}"
  if [[ -f "/etc/init.d/redis-server" ]]; then
    /etc/init.d/redis-server stop
  else
    systemctl stop redis-server
  fi

  echo -e "\\n""${ORANGE}""Removing redis-server packages""${NC}"
  apt-get purge redis-server -y || true
  echo -e "\\n""${ORANGE}""Removing mongod packages""${NC}"
  apt-get purge mongodb-org -y || true

  if [[ -f /etc/redis/redis.conf ]]; then
    echo -e "\\n""${ORANGE}""Removing redis configuration""${NC}"
    rm /etc/redis/redis.conf
  fi
  if [[ -f /etc/mongod.conf ]]; then
    echo -e "\\n""${ORANGE}""Removing EMBAs mongod configuration""${NC}"
    sed -i "s/bindIp\:\ ${MONGODB_HOST}/bindIp\:\ 127.0.0.1/g" /etc/mongod.conf    # inverse of IF20 line 118
  fi
  if [[ -f /etc/apt/sources.list.d/mongodb-org-4.4.list ]]; then
    echo -e "\\n""${ORANGE}""Removing mongod sources.list configuration""${NC}"
    rm /etc/apt/sources.list.d/mongodb-org-4.4.list
  fi
  apt-get update -y
  systemctl daemon-reload
  echo -e "\\n""${ORANGE}""Removing EMBA docker image""${NC}"
  docker image rm embeddedanalyzer/emba -f
  if [[ -d ./external ]]; then
    echo -e "\\n""${ORANGE}""Removing external directory""${NC}"
    rm -r ./external
  fi
  echo -e "\\n""${GREEN}""EMBA removed from system - please delete the current directory manually.""${NC}"
}
