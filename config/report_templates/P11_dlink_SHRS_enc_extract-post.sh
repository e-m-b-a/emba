#!/bin/bash

print_output "EMBA was able to identify an encrypted ${ORANGE}D'Link${NC} firmware image. This firmware image was protected with leaked key material and it is possible to decrypt the firmware for further analysis."
print_output ""
print_output "While EMBA is currently able to decrypt firmware with the header details ${ORANGE}SHRS${NC}, firmware with the header ${ORANGE}encrpted_img${NC} can't be decrypted by EMBA."
if [[ "$DLINK_ENC_DETECTED" -eq 1 ]]; then
  print_output ""
  print_output "In the current case the original firmware was encrypted with the ${ORANGE}SHRS${NC} mechanism and was decrypted to ${ORANGE}$EXTRACTION_FILE${NC}"
fi
