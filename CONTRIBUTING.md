# Contributing to *EMBA*

Contributions to *EMBA* are always welcome. This document explains the general requirements for contributions and the recommended preparation steps.
It also sketches the typical integration process of patches.

## 1) Contribution Checklist


- use git to manage your changes \[*recommended*]

- add the required copyright header to each new file introduced, see
  [licensing information](./LICENSE) \[**required**]

- structure patches logically, in small steps \[**required**]
  - one separable functionality/fix/refactoring = one patch
  - do not mix those three into a single patch (e.g., first refactor, then add a new functionality that builds onto the refactoring)
  - after each patch, *EMBA* has to work. Do not add
    even temporary breakages inside a patch series (helps when tracking down bugs)
  - use `git rebase -i` to restructure a patch series

- base patches on top of latest master or - if there are dependencies - on next
  (note: next is an integration branch that may change non-linearly)

- test your code with shellcheck \[**required**] 
  - see the included [codechecker script](./check_project.sh)
  - shellcheck should not be disabled on areas with issues -> solve these problems before the PR

- test your code in strict mode (EMBA parameter -S) \[**required**]
  - all code should be strict mode compatible

- send reminder if nothing happens after about a week

- feel free to mention [EMBA team members](https://github.com/orgs/e-m-b-a/people) in the issue/PR.

- the code needs to work on the latest Kali Linux and Ubuntu 22.04LTS (other distributions are welcome but currently not tested)

## 2) Code Guidelines

- General: Identation should be 2 spaces (no tab character)

- Comments: use # sign followed by a space. When needed, create a comment block. Blank lines: allowed

- If you are using an additional binary make sure it's available on the system before calling it
  - Include it into the dependency check and in the installer

- All functions use snake_case (e.g. `test_xyz()`). One blank lines between functions.

- Variables: Variables should be capitalized, with underscore as word separator (e.g. `PROCESS_EXISTS=1`)

- If you use external code, add `# Test source: \[LINK TO CODE]` above

- Scope of variables: Use local variables if possible

- Variables always need to be initialized
  - e.g., local lVARIABLE=""

- Local variables should always start with "l"
  - e.g., local lVARIABLE=""
  - Note: This will be enforced in the future!

- Local referenced ([nameref](https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameters)) variables should always start with "lr"
  - e.g., local -n lrVARIABLE="${1:-}"

- Use parameters to functions
  - work with local variables inside the functions
  - do not rely on globals if not needed

- Use `export` for variables which aren't only used in one function
  - From bash perspective it isn't necessary, but helps for readability

- We do not accept the usage of variables anymore that are not declared as local or external -> no indirect globals

- Don't use backticks anymore, use $(..) instead

- Don't use `grep -R` for recursive grep search. Instead use `find -type f -exec grep something {} \;` or use `grep -r`

- Use double square \[[]] brackets (conditional expressions) instead of single square [] brackets

- We require variable braces. Instead of using `$VARIABLE` please use `${VARIABLE}`

- Whenever possible try to avoid `tr` `sed` `awk` and use bash internal functions instead, see e.g. [bash shell parameter substitution](https://www.cyberciti.biz/tips/bash-shell-parameter-substitution-2.html). Using bash internals is faster as it does not fork, fopen and pipes the results back.

- At least ["weak quoting"](https://flokoe.github.io/bash-hackers-wiki/syntax/quoting/#quotes-and-escaping) is required - unquoted variable processing is not permitted

- To make an array unique we prefer using the printf methode instead of the eval methode: `mapfile -t ARRAY < <(printf "%s\n" "${ARRAY[@]}" | sort -u)`

- Ensure you are only working with printable characters (avoid using tr): `lVARIABLE=${lVARIABLE//[![:print:]]/}`

- Code tests: Use shellcheck and semgrep to test your code

- Code tests: The included `./check_project.sh` script performs multiple coding checks automatically. It is highly recommend to run this script before initiating a PR.

- Code tests: Run EMBA in STRICT mode (parameter -S) to ensure everything is correct (new code has to be STRICT mode compatible and needs to pass shellcheck and semgrep tests).
