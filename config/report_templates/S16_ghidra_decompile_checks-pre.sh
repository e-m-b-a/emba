#!/bin/bash

print_output "The following module tries to decompile the firmware binaries with Ghidra. Afterwards it tests the decompiled sources with semgrep for vulnerabilities."
print_output "Furhter details about the used approach are documented by ${ORANGE}0xdea${NC} in the following resources:"
print_output "$(indent "[*] ${ORANGE}https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/${NC}")"
print_output "$(indent "[*] ${ORANGE}https://github.com/0xdea/ghidra-scripts/blob/main/Haruspex.java${NC}")"
print_output "$(indent "[*] ${ORANGE}https://github.com/0xdea/semgrep-rules${NC}")"
