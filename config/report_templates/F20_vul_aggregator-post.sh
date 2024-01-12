#!/bin/bash

print_output "[*] Exploitability notes:"
print_output "$(indent "${ORANGE}R${NC} - remote exploits")"
print_output "$(indent "${ORANGE}L${NC} - local exploits")"
print_output "$(indent "${ORANGE}D${NC} - DoS exploits")"
# print_output "$(indent "${ORANGE}G${NC} - PoC code found on Github (unknown exploit vector)")"
# write_link "https://github.com/trickest/cve"
print_output "$(indent "${ORANGE}P${NC} - PoC code found on Packetstormsecurity (unknown exploit vector)")"
write_link "https://packetstormsecurity.com/files/tags/exploit/"
print_output "$(indent "${ORANGE}S${NC} - PoC code found on Snyk vulnerability database (unknown exploit vector)")"
write_link "https://security.snyk.io/vuln"
print_output "$(indent "${ORANGE}X${NC} - Vulnerability is known as exploited")"
write_link "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
print_output "$(indent "${ORANGE}V${NC} - Vulnerability verified - Kernel or BusyBox (S26, S118)")"

print_ln
print_ln
print_output "[*] Source notes:"
print_output "$(indent "${ORANGE}STAT${NC} - Details found by static modules (S06, S09, S24, S25)")"
print_output "$(indent "${ORANGE}PACK${NC} - Details found by package management environment (S08)")"
print_output "$(indent "${ORANGE}UEMU${NC} - Details found by dynamic user-mode emulation modules (S115, S116)")"
print_output "$(indent "${ORANGE}SEMU${NC} - Details found by dynamic system emulation modules (L*)")"
