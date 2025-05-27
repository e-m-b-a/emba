## Notes on the json configuration for version identification
* identifier: a unique identifier for this version detection entry (this entry should match the filename of the json file)
* parsing_mode: could be
  * normal - static analysis (default mode)
  * strict - needs also an affected_paths entry and these grep commands are only used on paths pattern
  * live - used in system emulation engine only
  * multi_grep - for multiple grep commands that must match
* licenses: one or more matching licenses
* grep_commands: grep commands that are executed for identification
* vendor_names: one or multiple vendor names that are used for CVE identification
* product_names: one or multiple product names that are used for CVE identification
* version_extraction: sed command to extract the minimal cpe identifier from the identified version
* affected_paths: for strict mode to check only these file/path patterns for the grep_commands

## final example

```
{
  "identifier": "busybox",
  "parsing_mode": [
    "live",
    "normal"
  ],
  "licenses": [
    "GPL-2.0-only"
  ],
  "grep_commands": [
    "\"BusyBox\\ v[0-9](\\.[0-9]+)+?.*\\ Built-in\\ shell\"",
    "\"BusyBox\\ v[0-9](\\.[0-9]+)+?.*\\ multi-call\\ binary\"",
    "\"BusyBox\\ v[0-9](\\.[0-9]+)+?\\ \\([0-9]+-.*\\)\"",
    "\"^BusyBox\\ http\\ [0-9](\\.[0-9]+)+?$\""
  ],
  "live_grep_commands": [
    "\"BusyBox\\ v[0-9](\\.[0-9]+)+?.*\\ Built-in\\ shell\""
  ],
  "vendor_names": [
    "busybox"
  ],
  "product_names": [
    "busybox"
  ],
  "version_extraction": [
    "\"sed -r 's/BusyBox\\ http\\ ([0-9](\\.[0-9]+)+?)$/:busybox:busybox:\\1/'\"",
    "\"sed -r 's/BusyBox\\ v([0-9](\\.[0-9]+)+?).*/:busybox:busybox:\\1/'\"",
    "\"sed -r 's/BusyBox\\ v([0-9](\\.[0-9]+)+?)\\ .*/:busybox:busybox:\\1/'\""
  ],
  "affected_paths": [
    "NA"
  ]
}
```
