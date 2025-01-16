<!-- 
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2020-2023 Siemens AG
Copyright 2020-2025 Siemens Energy AG

EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

EMBA is licensed under GPLv3

Author(s): Michael Messner, Pascal Eckmann, Benedikt Kühne
-->

<p align="center">
  <img src="./helpers/emba.svg" width="200"/>
</p>
<p align="center">
  <a href="https://github.com/koalaman/shellcheck"><img src="https://github.com/e-m-b-a/emba/workflows/ShellCheck/badge.svg?branch=master" /></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" /></a>
  <a href="https://github.com/e-m-b-a/emba/blob/master/LICENSE"><img src="https://img.shields.io/github/license/e-m-b-a/emba?label=License"></a>
  <a href="https://github.com/e-m-b-a/emba/graphs/contributors"><img src="https://img.shields.io/github/contributors/e-m-b-a/emba?color=9ea"></a>
  <a href="https://github.com/e-m-b-a/emba/stargazers"><img src="https://img.shields.io/github/stars/e-m-b-a/emba?label=Stars"></a>
  <a href="https://github.com/e-m-b-a/emba/network/members"><img src="https://img.shields.io/github/forks/e-m-b-a/emba?label=Forks"></a>
  <a href="https://hub.docker.com/r/embeddedanalyzer/emba"><img src="https://img.shields.io/docker/pulls/embeddedanalyzer/emba"></a>
  <a href="https://twitter.com/intent/tweet?text=Check%20out%20EMBA%20-%20The%20Firmware%20security%20scanner!%20https://github.com/e-m-b-a/emba"><img src="https://img.shields.io/twitter/url.svg?style=social&url=https%3A%2F%2Fgithub.com%2Fe-m-b-a%2Femba"></a>
</p>

# EMBA
## The security analyzer for firmware of embedded devices

*EMBA* is designed as the central firmware analysis and SBOM tool for penetration testers, product security teams, developers and responsible product managers. It supports the complete security analysis process starting with *firmware extraction*, doing *static analysis* and *dynamic analysis* via emulation, building the SBOM and finally generating a web based vulnerability report. *EMBA* automatically discovers possible weak spots and vulnerabilities in firmware. Examples are insecure binaries, old and outdated software components, potentially vulnerable scripts, or hard-coded passwords. *EMBA* is a command line tool with the possibility to generate an easy-to-use web report for further analysis.

*EMBA* assists the penetration testers, product security teams and developers in the identification of weak spots and vulnerabilities in the firmware image. *EMBA* provides as much information as possible about the firmware, that the tester can decide on focus areas and is responsible for verifying and interpreting the results.

[![Watch EMBA](https://raw.githubusercontent.com/wiki/e-m-b-a/emba/images/youtube-emba.png)](https://youtu.be/_dvdy3klFFY "Watch EMBA")

----------------------

#### Links to the wiki for more detailed information

- [Home](https://github.com/e-m-b-a/emba/wiki)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
- [Usage](https://github.com/e-m-b-a/emba/wiki/Usage)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)

## Installation

Before running *EMBA* make sure, that you have [installed](https://github.com/e-m-b-a/emba/wiki/Installation) all dependencies with the installation script and met the [prerequisites](https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites)

```console
git clone https://github.com/e-m-b-a/emba.git
cd emba
sudo ./installer.sh -d
```

## Quick start with default scan profile:
```console
sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-scan.emba

```
## Quick start with default SBOM profile:
For further details on EMBA's SBOM capabilities check the [wiki](https://github.com/e-m-b-a/emba/wiki/SBOM-environment)
```console
sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-sbom.emba

```
## Quick start with system-emulation scan profile:
For further details on EMBA's system-emulation engine check the [wiki](https://github.com/e-m-b-a/emba/wiki/System-emulation).
```console
sudo ./emba -l ~/log -f ~/firmware -p ./scan-profiles/default-scan-emulation.emba

```

---
*EMBA* supports multiple testing and reporting [options](https://github.com/e-m-b-a/emba/wiki/Usage#arguments). For more details check the [wiki](https://github.com/e-m-b-a/emba/wiki/Usage).

## Get involved
The IoT is growing, the development is ongoing, and there are many new features that we want to add.
We welcome [pull requests](https://github.com/e-m-b-a/emba/pulls) and [issues](https://github.com/e-m-b-a/emba/issues) on GitHub. Also check the [CONTRIBUTING](./CONTRIBUTING.md) and [CONTRIBUTORS](./CONTRIBUTORS.md) documentation for further details on how to get part of the _EMBA_ commmunity.

## Team

[The core EMBA Team](https://github.com/orgs/e-m-b-a/people)

[Contributors](https://github.com/e-m-b-a/emba/blob/master/CONTRIBUTORS.md)
