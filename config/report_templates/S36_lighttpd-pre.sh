#!/bin/bash

print_output "This module tests for lighttpd configuration files and binaries"
print_output "The configuration files are analysed for configuration issues."
print_ln
print_output "The tests of these configuration files is based on the following sources:"
print_output "$(indent "$(orange "- Lighttpd - Docs_SSL")")"
write_link "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL"
print_output "$(indent "$(orange "- Alpine Linux - Lighttpd Advanced security")")"
write_link "https://wiki.alpinelinux.org/wiki/Lighttpd_Advanced_security"
print_output "$(indent "$(orange "- Hardening guide for lighttpd 1.4.26 on redhat Linux")")"
write_link "https://security-24-7.com/hardening-guide-for-lighttpd-1-4-26-on-redhat-5-5-64bit-edition/"