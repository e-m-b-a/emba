#!/bin/bash

EMBA_CONFIG_PATH="./config"
EMBA_EXT_DIR="./external"
TRICKEST_DB_PATH="$EMBA_CONFIG_PATH"/trickest_cve-db.txt

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if ! [[ -d "$EMBA_CONFIG_PATH" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi

echo -e "[*] Update the trickest database\n"
if [[ -f "$TRICKEST_DB_PATH" ]]; then
  echo -e "${GREEN}[*] Trickest CVE database has $ORANGE$(wc -l "$TRICKEST_DB_PATH" | awk '{print $1}')$GREEN exploit entries (before update).$NC"
fi

if [[ -d "$EMBA_EXT_DIR"/trickest-cve ]]; then
  echo "[*] Update and build the Trickest CVE/exploit database"
  cd "$EMBA_EXT_DIR"/trickest-cve || (echo "[-] Something was going wrong during trickest update" && exit 1)
  git pull || (echo "[-] Something was going wrong during trickest update" && exit 1)
  cd ../.. || (echo "[-] Something was going wrong during trickest update" && exit 1)
else
  echo "[*] Clone and build the Trickest CVE/exploit database"
  git clone https://github.com/trickest/cve.git "$EMBA_EXT_DIR"/trickest-cve || (echo "[-] Something was going wrong during trickest update" && exit 1)
fi

if [[ -d "$EMBA_EXT_DIR"/trickest-cve ]]; then
  find "$EMBA_EXT_DIR"/trickest-cve -type f -iname "*.md" -exec grep -o -H "^\-\ https://github.com.*" {} \; | sed 's/:-\ /:/g' | sort > "$TRICKEST_DB_PATH" || (echo "[-] Something was going wrong during trickest update" && exit 1)

  # if we have a blacklist file we are going to apply it to the generated trickest database
  if [[ -f "$EMBA_CONFIG_DIR"/trickest_blacklist.txt ]] && [[ -f "$TRICKEST_DB_PATH" ]]; then
    grep -Fvf "$EMBA_CONFIG_DIR"/trickest_blacklist.txt "$TRICKEST_DB_PATH" > /tmp/trickest_db-cleaned.txt || (echo "[-] Something was going wrong during trickest update" && exit 1)
    mv "$EXT_DIR"/trickest_db-cleaned.txt "$TRICKEST_DB_PATH" || (echo "[-] Something was going wrong during trickest update" && exit 1)
  fi

  if [[ -f "$TRICKEST_DB_PATH" ]]; then
    echo -e "${GREEN}[+] Trickest CVE database now has $ORANGE$(wc -l "$TRICKEST_DB_PATH" | awk '{print $1}')$GREEN exploit entries (after update)."
  fi
else
  echo "[-] No update of the Trickest exploit database performed."
fi
