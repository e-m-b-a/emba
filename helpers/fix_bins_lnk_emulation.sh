#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Walk through a root directory and fix ELF permissions. Additionally
#               this script also tries to fix sym links which are regularly broken

BUSYBOX="/busybox"

ROOT_DIR="${1:-}"
if ! [[ -d "${ROOT_DIR}" ]]; then
  echo "[-] No valid root directory provided - Fix links and bin permissions failed"
  exit
fi

cp "$(command -v busybox)" "$ROOT_DIR"
chmod +x "$ROOT_DIR"/busybox

echo "[*] Identifying possible ELF files"
mapfile -t POSSIBLE_ELFS < <(find "$ROOT_DIR" -type f -exec file {} \; | grep ELF | cut -d: -f1)

for POSSIBLE_ELF in "${POSSIBLE_ELFS[@]}"; do
  echo "[*] Processing ELF $(basename "$POSSIBLE_ELF") - chmod privileges"
  chmod +x "$POSSIBLE_ELF"
done

HOME_DIR="$(pwd)"
if [[ -d "$ROOT_DIR" ]]; then
  cd "$ROOT_DIR" || exit 1
else
  exit 1
fi

echo ""
echo "[*] Identifying possible symlinks"
mapfile -t POSSIBLE_DEAD_SYMLNKS < <(find "." -type f -exec file {} \; | grep data | cut -d: -f1)

for POSSIBLE_DEAD_SYMLNK in "${POSSIBLE_DEAD_SYMLNKS[@]}"; do
  if [[ "$(strings "$POSSIBLE_DEAD_SYMLNK" | wc -l)" -eq 0 ]] || [[ "$(strings "$POSSIBLE_DEAD_SYMLNK" | wc -l)" -gt 1 ]]; then
    continue
  fi

  TMP_LNK_ORIG=$(strings "$POSSIBLE_DEAD_SYMLNK")
  TMP_LNK=${TMP_LNK_ORIG/\.\.\//}
  POSSIBLE_SYMLNK_NAME=${POSSIBLE_DEAD_SYMLNK/\./}

  mapfile -t POSSIBLE_MATCHES < <(find "." -wholename "*$TMP_LNK")
  for MATCH in "${POSSIBLE_MATCHES[@]}"; do
    if [[ "$MATCH" == "./busybox" ]]; then
      continue
    fi
    MATCH=${MATCH/\./}
    echo -e "[*] Symlink file $POSSIBLE_SYMLNK_NAME - $MATCH"
    chroot . "$BUSYBOX" rm "$POSSIBLE_DEAD_SYMLNK"
    chroot . "$BUSYBOX" ln -s "$MATCH" "$POSSIBLE_SYMLNK_NAME"
  done
done

cd "$HOME_DIR" || exit 1
rm "$ROOT_DIR"/busybox
