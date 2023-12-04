#!/bin/bash

print_output "This module tries to identify interesting areas within the firmware with the tool grepit from the CRASS (code review audit script scanner) toolbox."
print_output "The grepit module name starts with a priority value between 1-9, where 1 is more interesting (low false positive rate, certainty of vulnerability) and 9 is only something you might want to have a look when you are desperately looking for vulnerabilities"