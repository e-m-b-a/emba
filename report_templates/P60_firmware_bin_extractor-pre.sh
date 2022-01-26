#!/bin/bash

print_output "This module extracts firmware with binwalk, checks if a root filesystem can be found."
print_output "If binwalk fails to extract the firmware, FACT-extractor is used."
print_output "As last resort binwalk will try to extract every available file multiple times."
print_output ""
print_output "If archives like apk, ipk or deb are found they are also extracted to the root filesystem."
print_output ""
