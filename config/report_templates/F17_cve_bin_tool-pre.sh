#!/bin/bash

print_output "This module aggregates all found version numbers together from S06, S08, S09, S24, S25 and S115 and searches with cve-bin-tool for known vulnerabilities."
print_output "Additionally, the identified CVE details are matched with EPSS, public exploit databases and a VEX json is generated."
