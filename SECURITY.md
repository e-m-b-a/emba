# Security Policy

_EMBA_ is a platform for optimizing our research and testing tasks in the field of IoT, OT, ICS and general embedded analysis. Because of this, we include code quite early and sometimes in a very raw state. We do not recommend setting up _EMBA_ as a productive environment or in an unprotected environment! If you are using _EMBA_ you should know what you are doing.

# WARNING

_EMBA_ is using multiple protections layers like chroot, docker, read-only filesystem, non executable mounts and disabled networking functionality.
Nevertheless, _EMBA_ should only be used on test systems! It should not be installed/deployed on production systems.

There are multiple reasons for that:
* The _EMBA_ docker container is running in privileged mode which will result in full system compromise if you are testing malicious firmware.
* _EMBA_ automatically executes untrusted code from the firmware which could lead to breakouts that are able to compromise the host system.
* _EMBA_ automatically builds and boots a firmware image based on the untrusted firmware under test.

## Reporting a Vulnerability

If there is a security problem within _EMBA_ please open an issue or contact us via one of the following ways:
* [Open an Issue](https://github.com/e-m-b-a/emba/issues)
* [Start a Discussion](https://github.com/e-m-b-a/emba/discussions)
* [PM us via Twitter](https://twitter.com/securefirmware)
* [PM us via Mastodon](https://infosec.exchange/@securefirmware)
