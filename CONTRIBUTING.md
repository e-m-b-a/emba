# Contributing to *emba*
Contributions to *emba* are always welcome. This document explains the general requirements for contributions and the recommended preparation steps. 
It also sketches the typical integration process of patches.

## 1) Contribution Checklist


- use git to manage your changes [*recommended*]

- add the required copyright header to each new file introduced, see
  [licensing information](./LICENSE) [**required**]

- structure patches logically, in small steps [**required**]
    - one separable functionality/fix/refactoring = one patch
    - do not mix those three into a single patch (e.g., first refactor, then add a new functionality that builds onto the refactoring)
    - after each patch, *emba* has to work. Do not add
      even temporary breakages inside a patch series (helps when tracking down bugs)
    - use `git rebase -i` to restructure a patch series

- base patches on top of latest master or - if there are dependencies - on next
  (note: next is an integration branch that may change non-linearly)

- add signed-off to all patches [**required**]
    - to certify the "Developer's Certificate of Origin", see below
    - check with your employer when not working on your own!

- test your code with shellcheck [**required**] 
    -  see the included [shellchecker script](./check_project.sh)

- send reminder if nothing happens after about a week

- the code needs to work on the latest Kali Linux (other distributions are welcome but currently not tested)

## 2) Code Guidelines

- General: Identation should be 2 spaces (no tab character)

- Comments: use # sign followed by a space. When needed, create a comment block. Blank lines: allowed

- All functions use snake_case (e.g. `test_xyz()`). One blank lines between functions.

- Variables: Variables should be capitalized, with underscore as word separator (e.g. `PROCESS_EXISTS=1`)

- If you use external code, add `# Test source: [LINK TO CODE]` above

- Scope of variables: Use local variables if possible

- Use `export` for variables which aren't only used in one file - it isn't necessary, but helps for readability

- Code tests: Use shellcheck to test your code (./check_project.sh)

## 3) Developer's Certificate of Origin 1.1

When signing-off a patch for this project like this

    Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (no pseudonyms or anonymous contributions), you declare the
following:

    By making a contribution to this project, I certify that:

        (a) The contribution was created in whole or in part by me and I
            have the right to submit it under the open source license
            indicated in the file; or

        (b) The contribution is based upon previous work that, to the best
            of my knowledge, is covered under an appropriate open source
            license and I have the right under that license to submit that
            work with modifications, whether created in whole or in part
            by me, under the same open source license (unless I am
            permitted to submit under a different license), as indicated
            in the file; or

        (c) The contribution was provided directly to me by some other
            person who certified (a), (b) or (c) and I have not modified
            it.

        (d) I understand and agree that this project and the contribution
            are public and that a record of the contribution (including all
            personal information I submit with it, including my sign-off) is
            maintained indefinitely and may be redistributed consistent with
            this project or the open source license(s) involved.

See also https://www.kernel.org/doc/Documentation/process/submitting-patches.rst
(Section 11, "Sign your work") for further background on this process which was
adopted from the Linux kernel.
