# Version identifier test data

This subdirectory contains the coverage statistics for the version
identifier test data of the EMBA module `S09_firmware_base_version_check`.

## Purpose

The EMBA module `S09_firmware_base_version_check` detects embedded
software versions by grepping the `strings` output of firmware binaries
with the regex patterns defined in `config/bin_version_identifiers/*.json`.

Instead of copying entire firmware binaries into the test suite (which can
be 100+ MB), `../../bin_version_testdata/*.bin` holds only the relevant byte
windows around the grep matches. Every test bin is named
`<identifier>_<grep id>.bin`, following the corpus naming of
`create_minimal_binary_corpus` in
`../../../modules/S09_firmware_base_version_check.sh`.

## Statistics

`../../bin_version_testdata` is compared against all static rules of
`../../../config/bin_version_identifiers` by
`../../modules/s09_bin_version_identifiers.bats`. It reports how many grep
entries are matched by a test bin, how many are missing a test bin and which
test bins are stale or orphaned.

```
./tests/scripts/bin_version_testdata/coverage_report.sh
```

bats hides the output of passing tests, so this runner enables the output of
passing tests and prints the statistics always - not just on failure. It is
also called at the end of `./tests/run.sh`.

## How matching works

The check mirrors `S09_firmware_base_version_check`:

1. `AND` multi greps are split into their sub-identifiers.
2. Leading/trailing `'` and surrounding `"` are stripped per element.
3. Anchors are dropped, as the test bins are extracted as context windows
   around the matches.
4. Each element is tested with `grep -a -q -o -E` against the test bin.
