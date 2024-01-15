#!/bin/bash

print_output "The kernel verification module extracts the kernel symbols and matches these symbols against the CVE data. The CVE data was first collected from the version identifier only."
print_output "Additionally, this module tries to compile the kernel with a configuration file that was extracted from module s24. This technique was first documented here: https://arxiv.org/pdf/2209.05217.pdf"
