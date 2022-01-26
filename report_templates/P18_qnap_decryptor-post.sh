#!/bin/bash

print_output "EMBA was able to identify an encrypted ${ORANGE}QNAP${NC} firmware image. This firmware image was protected with leaked key material and it is possible to decrypt the firmware for further analysis."
print_output ""
print_output "The original firmware was decrypted to ${ORANGE}$EXTRACTION_FILE${NC}"
