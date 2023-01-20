#!/bin/bash

EMBA_CONFIG_PATH="./config"
MSF_DB_PATH="$EMBA_CONFIG_PATH"/msf_cve-db.txt
MSF_MOD_PATH="/usr/share/metasploit-framework/modules/"

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if ! [[ -d "$EMBA_CONFIG_PATH" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi
if ! [[ -d "$MSF_MOD_PATH" ]]; then
  echo "[-] No Metasploit directory found! Please install Metasploit and re-try it"
  echo "[*] Current Metasploit directory configuration: $ORANGE$MSF_MOD_PATH$NC."
  exit 1
fi

if [[ -f "$MSF_DB_PATH" ]]; then
  echo -e "${GREEN}[*] Metasploit exploit database has $ORANGE$(wc -l "$MSF_DB_PATH" | awk '{print $1}')$GREEN exploit entries (before update).$NC"
fi

echo "[*] Updating the Metasploit framework package"
sudo apt-get update -y
sudo apt-get --only-upgrade install  metasploit-framework -y

echo "[*] Building the Metasploit exploit database"
# search all ruby files in the metasploit directory and create a temporary file with the module path and CVE:
find "$MSF_MOD_PATH" -type f -iname "*.rb" -exec grep -H -E -o "CVE', '[0-9]{4}-[0-9]+" {} \; | sed "s/', '/-/g" | sort > "$MSF_DB_PATH"

if [[ -f "$MSF_DB_PATH" ]]; then
  echo -e "${GREEN}[*] Metasploit exploit database now has $ORANGE$(wc -l "$MSF_DB_PATH" | awk '{print $1}')$GREEN exploit entries (after update).$NC"
fi
