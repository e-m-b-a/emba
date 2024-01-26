#!/bin/bash

print_output "First, this module extracts the BusyBox vulnerabilities based on version details."
print_output "Second, the enabled applets are extracted from the emulation results of module s115/s116."
print_output "Finally, the already known vulnerabilities are matched against the extracted applets. Vulnerability descriptions with matching applets are rated as verified CVEs"
