#!/bin/bash
# shellcheck disable=SC2001

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Aggregates all found version numbers together from R09, S09, S25 and S115 and searches with cve-search for all CVEs, 
#               then it lists exploits that could possible be used for the firmware.

F19_cve_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final CVE aggregator"
  
  mkdir "$LOG_PATH_MODULE"/cve_sum
  mkdir "$LOG_PATH_MODULE"/exploit

  KERNELV=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  CVE_SEARCHSPLOIT=0
  MSF_MODULE_CNT=0

  CVE_AGGREGATOR_LOG="f19_cve_aggregator.txt"
  FW_VER_CHECK_LOG="s09_firmware_base_version_check.txt"

  S06_LOG="s06_distribution_identification.txt"
  KERNEL_CHECK_LOG="s25_kernel_check.txt"
  EMUL_LOG="s115_usermode_emulator.txt"
  SYS_EMUL_LOG="l15_emulated_checks_init.txt"

  CVE_MINIMAL_LOG="$LOG_PATH_MODULE"/CVE_minimal.txt
  EXPLOIT_OVERVIEW_LOG="$LOG_PATH_MODULE"/exploits-overview.txt

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    get_kernel_check
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ ${#VERSIONS_KERNEL[@]} -ne 0 ]]; then
      # then we have found a kernel in our s25 kernel module
      KERNELV=1
    fi

    get_firmware_details
    get_firmware_base_version_check
    get_usermode_emulator
    get_systemmode_emulator

    aggregate_versions
    
    # Mongo DB is running on Port 27017. If not we can't check CVEs
    if [[ $(netstat -ant | grep -c 27017) -eq 0 && $IN_DOCKER -eq 0 ]]; then
      print_output "[*] Trying to start the vulnerability database"
      systemctl restart mongod
      sleep 2
    fi

    if [[ $(netstat -ant | grep -c 27017) -gt 0 ]]; then
      if command -v cve_searchsploit > /dev/null ; then
        CVE_SEARCHSPLOIT=1
      fi
      if [[ -f "$MSF_DB_PATH" ]]; then
        MSF_SEARCH=1
      fi

      generate_cve_details
      generate_special_log
    else
      print_output "[-] MongoDB not running on port 27017."
      print_output "[-] CVE checks not possible!"
      print_output "[-] Have you installed all the needed dependencies?"
      print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
    fi
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Run the installer or install it from here: https://github.com/cve-search/cve-search."
    print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
  fi

  FOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$LOG_FILE" | grep -c -E "\[\+\]\ Found\ ")

  module_end_log "${FUNCNAME[0]}" "$FOUND_CVE"
}

prepare_version_data() {
    #print_output "$VERSION_lower"
    # we try to handle as many version strings as possible through these generic rules
    VERSION_lower="$(echo "$VERSION" | tr '[:upper:]' '[:lower:]')"
    # tab -> space
    # remove multiple spaces
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/[[:space:]]\+/\ /g')"
    VERSION_lower="${VERSION_lower//\ in\ extracted\ firmware\ files\ \(static\)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ original\ firmware\ file\ (static)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ extraction\ logs\ (static)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ binwalk\ logs\ (static)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ binwalk\ logs./\ }"
    VERSION_lower="${VERSION_lower//\ in\ qemu\ log\ file\ (emulation)\./\ }"
    VERSION_lower="${VERSION_lower//\ for\ d-link\ device\./\ }"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ in\ binary\ .*\./\ /g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ in\ kernel\ image\ .*\./\ /g')"

    #lvmetad version: 2.02.168(2) (2016-11-30)  #lvmpolld version: 2.02.168(2) (2016-11-30)
    VERSION_lower="${VERSION_lower/lvmpolld\ /lvm2\ }"
    VERSION_lower="${VERSION_lower/lvmetad\ /lvm2\ }"
    #ldpd version 0.99.24.1 #ospf6d version 0.99.24.1 #etc.
    VERSION_lower="$(echo "$VERSION_lower" | sed -E -e 's/(\bldpd|linkd|ospf6d|ripngd|zebra|ripd|babeld|bgpd)\ version\ 0.9/quagga\ 0.9/')"
    #bridge utility, 0.0
    VERSION_lower="${VERSION_lower/bridge\ utility/bridge-utility}"
    # smbd -> samba
    VERSION_lower="${VERSION_lower/smbd/samba}"
    # jq-1.5 -> jq 1.5
    VERSION_lower="${VERSION_lower/jq-/jq\ }"
    #Modern traceroute for Linux, version 2.1.0
    VERSION_lower="${VERSION_lower/modern\ traceroute\ for\ linux/traceroute}"
    #signver - verify a detached PKCS7 signature - Version 3.26.2
    VERSION_lower="${VERSION_lower/\ -\ verify\ a\ detached\ pkcs7\ signature\ -/}"
    #part of minicom version 2.7
    VERSION_lower="${VERSION_lower/part\ of\ minicom/minicom}"
    # part of SSLeay 0.8.1 19-Jul-1997A
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/part\ of\ ssleay\ ([0-9]\.[0-9]+\.[0-9]+)\ [0-9]+.*/ssleay\ \1/')"
    # Welcome to QNX Neutrino 1.2.3
    VERSION_lower="${VERSION_lower/welcome\ to\ qnx\ neutrino/qnx_neutrino_rtos}"
    #run-parts program, version 4.8.1.1
    VERSION_lower="${VERSION_lower/run-parts\ program,/run-parts}"
    #GNU parted) 3.2
    VERSION_lower="${VERSION_lower/gnu\ parted\)/parted}"
    #pax-utils-v1.2.8:
    VERSION_lower="${VERSION_lower/pax-utils-v/pax-utils\ }"
    #(tzcode) 
    VERSION_lower="${VERSION_lower/\(tzcode\)\ /tzcode\ }"
    # #mkenvimage version 2016.11+dfsg1-4
    # VERSION_lower="${VERSION_lower/mkenvimage\ /u-boot\ }"
    # #mkimage version 2016.11+dfsg1-4
    VERSION_lower="$(echo "$VERSION_lower" | sed -E -e 's/(mkenvimage|mkimage|dumpimage)\ version\ 20/u-boot\ 20/')"
    # VERSION_lower="${VERSION_lower/mkimage\ /u-boot\ }"
    #Version: lldpd 0.7.11
    VERSION_lower="${VERSION_lower/version:\ lldpd\ /lldpd\ }"
    #cdialog (ComeOn Dialog!) version 1.3-20160828
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(cdialog).*(version [0-9]\.[0-9])/\1\ \2/')"
    #(OpenRC) 0.42.1.7888a888
    #VERSION_lower="${VERSION_lower/\(openrc\)\ /openrc\ }"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\(openrc\)\ ([0-9])\.([0-9]+)\.([0-9]+)\..*/openrc \1\.\2\.\3/')"
    #atftp-0.7
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(atftp)-([0-9]\.[0-9])/\1\ \2/')"
    #radiusd: FreeRADIUS Version 2.2.2
    VERSION_lower="${VERSION_lower/radiusd:\ freeradius/freeradius}"
    #Btrfs Btrfs v0.19
    VERSION_lower="${VERSION_lower/btrfs\ btrfs/btrfs}"
    #ethswctl.c:v0.0.2 (January 27, 2009)
    VERSION_lower="${VERSION_lower//ethswctl.c:v/ethswctl\ }"
    #ftpd (GNU inetutils) 1.4.2
    VERSION_lower="${VERSION_lower//\(gnu inetutils\)/inetutils}"
    #conntrack v1.0.0 (conntrack-tools)
    VERSION_lower="${VERSION_lower/conntrack/conntrack-tools}"
    #chronyc (chrony) version 3.5 (-READLINE -SECHASH +IPV6 -DEBUG)
    VERSION_lower="${VERSION_lower//chrony[cd] \(chrony\) /chrony }"
    # GNU gdbserver (GDB)
    VERSION_lower="${VERSION_lower//gnu\ gdbserver\ /gdb\ }"
    VERSION_lower="${VERSION_lower//(gdb)\ /}"
    #udevadm -> systemd
    VERSION_lower="${VERSION_lower//udevadm/systemd}"
    # some - -> space
    VERSION_lower="${VERSION_lower//acpid-/acpid\ }"
    VERSION_lower="${VERSION_lower//linux-/linux\ }"
    # alsactl, amixer -> alsa
    VERSION_lower="${VERSION_lower//alsactl/alsa}"
    VERSION_lower="${VERSION_lower//amixer/alsa}"
    # ipsec ...
    VERSION_lower="${VERSION_lower//ipsec\ _copyright/ipsec}"
    VERSION_lower="${VERSION_lower//ipsec\ eroute/ipsec}"
    VERSION_lower="${VERSION_lower//ipsec\ ranbits/ipsec}"
    #fota client version: 0.1.5.
    VERSION_lower="${VERSION_lower//fota\ client\ version:/fota}"
    #sudoreplay -> sudo
    VERSION_lower="${VERSION_lower//sudoreplay/sudo}"
    #visudo -> sudo
    VERSION_lower="${VERSION_lower//visudo/sudo}"
    # VIM - Vi IMproved 1.2
    VERSION_lower="${VERSION_lower//vim\ -\ vi\ improved/vim}"
    #zic.c
    VERSION_lower="${VERSION_lower//zic\.c/zic}"
    #bzip2, a block-sorting file compressor.  Version 1.0.6, 
    VERSION_lower="${VERSION_lower//bzip2,\ a\ block-sorting\ file\ compressor\.\ version/bzip2}"
    VERSION_lower="${VERSION_lower//bzip2recover/bzip2}"
    # gnutls
    VERSION_lower="${VERSION_lower//enabled\ gnutls/gnutls}"
    VERSION_lower="${VERSION_lower//project-id-version:\ gnutls/gnutls}"
    #jQuery JavaScript Library v1.4.3
    VERSION_lower="${VERSION_lower//jquery\ javascript\ library\ v/jquery\ }"
    # GNU Midnight Commander 
    VERSION_lower="${VERSION_lower//gnu\ midnight\ commander/midnight_commander}"
    #xl2tpd version:  xl2tpd-1.3.6
    VERSION_lower="${VERSION_lower//xl2tpd\ version\:\ xl2tpd-/xl2tp\ }"
    VERSION_lower="${VERSION_lower//xl2tpd\ server\ xl2tpd-/xl2tpd\ }"
    VERSION_lower="${VERSION_lower//goahead\ /goahead\ }"
    # nc.traditional:strict:"\[v[0-9]\.[0-9]+-[0-9]+\]$"
    VERSION_lower="${VERSION_lower//nc.traditional\ \[v/nc.traditional\ }"
    # sqlite3 -> sqlite
    VERSION_lower="${VERSION_lower//sqlite3/sqlite}"
    # strict libsqlite3.so.0 -> sqlite
    VERSION_lower="${VERSION_lower//libsqlite3\.so\.0/sqlite}"
    # dnsmasq- -> dnsmasq 
    VERSION_lower="${VERSION_lower//dnsmasq-/dnsmasq\ }"
    # lighttpd- -> lighttpd\ 
    VERSION_lower="${VERSION_lower//lighttpd-/lighttpd\ }"
    #lighttpd/1.4.33-devel-17M (Nov 13 2013 21:55:13) - a light and fast webserver
    VERSION_lower="${VERSION_lower//lighttpd\//lighttpd\ }"
    VERSION_lower="$(echo "$VERSION_lower" | sed "s/-devel-17m//")"
    # Compiled\ with\ U-Boot -> u-boot
    VERSION_lower="${VERSION_lower//compiled\ with\ u-boot/u-boot }"
    #tcpdump.4.6.2 version
    VERSION_lower="${VERSION_lower//tcpdump\./tcpdump\ }"
    #ntpd\ -\ standard\ NTP\ query\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//ntpd\ -\ ntp\ daemon\ program\ -\ ver\.\ /ntpd\ }"
    VERSION_lower="${VERSION_lower//ntpq\ -\ standard\ ntp\ query\ program\ -\ ver\.\ /ntpq\ }"
    #This is SMTPclient Version
    VERSION_lower="${VERSION_lower//this\ is\ smtpclient/smtpclient}"
    #btconfig - BTCONFIG Tool ver
    VERSION_lower="${VERSION_lower//-\ btconfig\ tool\ ver/}"
    # hciemu - HCI emulator ver 
    VERSION_lower="${VERSION_lower//-\ hci\ emulator\ ver/}"
    # hcitool - HCI Tool ver 
    VERSION_lower="${VERSION_lower//-\ hci\ tool\ ver/}"
    # sdptool - SDP tool 
    VERSION_lower="${VERSION_lower//-\ sdp\ tool/}"
    # iputils-sss
    VERSION_lower="${VERSION_lower//iputils-sss/iputils\ }"
    #iproute2-ss040823 -> iproute2-2_6_8-040823
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/iproute2-ss(040823)/iproute2\ 2\.6\.8\-\1/')"
    VERSION_lower="${VERSION_lower//iproute2-ss/iproute2\ }"
    #nettle-hash\ (nettle\ -> nettle
    VERSION_lower="${VERSION_lower//nettle-hash\ ./}"
    # if we have a version string like "binary version v1.2.3" we have to remove the version and the v:
    VERSION_lower="${VERSION_lower//\ version\:/}"
    VERSION_lower="${VERSION_lower//version\ /}"
    # ubiXYZ -> mtd-utils
    VERSION_lower="${VERSION_lower//ubinfo/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiattach/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubidetach/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubimkvol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubirmvol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiblock/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiupdatevol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubicrc32/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubinize/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiformat/mtd-utils}"
    VERSION_lower="${VERSION_lower//mtdinfo/mtd-utils}"
    VERSION_lower="${VERSION_lower//nandwrite/mtd-utils}"
    VERSION_lower="${VERSION_lower//nanddump/mtd-utils}"
    VERSION_lower="${VERSION_lower//flash_erase/mtd-utils}"
    #flashcp (mtd-utils) 2.0.2
    VERSION_lower="${VERSION_lower//\(mtd-utils\)/mtd-utils}"
    # mount.cifs -> cifs-utils
    VERSION_lower="${VERSION_lower//mount\.cifs/cifs-utils}"
    # lspci, setpci -> pciutils
    VERSION_lower="${VERSION_lower//lspci/pciutils}"
    VERSION_lower="${VERSION_lower//setpci/pciutils}"
    # zlib:binary:"deflate\ [0-9]\.[0-9]+\.[0-9]+\ Copyright.*Mark\ Adler"
    # zlib:binary:"inflate\ [0-9]\.[0-9]+\.[0-9]+\ Copyright.*Mark Adler"
    VERSION_lower="${VERSION_lower//deflate/zlib}"
    VERSION_lower="${VERSION_lower//inflate/zlib}"
    # e2fsprogs
    VERSION_lower="${VERSION_lower//debugfs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//dumpe2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//e2fsck/e2fsprogs}"
    VERSION_lower="${VERSION_lower//e2image/e2fsprogs}"
    VERSION_lower="${VERSION_lower//mke2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//resize2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//tune2fs/e2fsprogs}"
    # ntfsprogs
    VERSION_lower="${VERSION_lower//mkntfs/ntfsprogs}"
    VERSION_lower="${VERSION_lower//ntfsck/ntfsprogs}"
    VERSION_lower="${VERSION_lower//ntfsresize/ntfsprogs}"
    VERSION_lower="${VERSION_lower//ntfsfix/ntfsprogs}"
    VERSION_lower="${VERSION_lower//ntfsck/ntfsprogs}"
    VERSION_lower="${VERSION_lower//ntfsdecrypt/ntfsprogs}"
    #ntfslabel -> ntfs-3g
    VERSION_lower="${VERSION_lower//ntfslabel/ntfs-3g}"
    #i2cXYZ -> i2c-tools
    VERSION_lower="${VERSION_lower//i2cdetect/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cdump/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cget/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cset/i2c-tools}"
    # xfs_db -> xfsprogs
    VERSION_lower="${VERSION_lower//xfs_db/xfsprogs}"
    VERSION_lower="${VERSION_lower//xfs_growfs/xfsprogs}"
    VERSION_lower="${VERSION_lower//xfs_repair/xfsprogs}"
    VERSION_lower="${VERSION_lower//mkfs.xfs/xfsprogs}"
    #manxyz -> man-db
    VERSION_lower="${VERSION_lower//mandb/man-db}"
    VERSION_lower="${VERSION_lower//manpath/man-db}"
    VERSION_lower="${VERSION_lower//catman/man-db}"
    VERSION_lower="${VERSION_lower//globbing/man-db}"
    VERSION_lower="${VERSION_lower//lexgrog/man-db}"
    #jfsxyz -> jfsutils
    VERSION_lower="${VERSION_lower//jfs_fscklog/jfsutils}"
    VERSION_lower="${VERSION_lower//jfs_tune/jfsutils}"
    # expat_1.1.1 -> expat 1.1.1
    VERSION_lower="${VERSION_lower//expat_/expat\ }"
    #file-
    VERSION_lower="${VERSION_lower//file-/file\ }"
    #libpcre.1.2.3
    VERSION_lower="${VERSION_lower//libpcre\.so\./pcre\ }"
    VERSION_lower="${VERSION_lower//pppd\.so\./pppd\ }"
    #pppd version 2.4.2
    VERSION_lower="${VERSION_lower/pppd/point-to-point_protocol}"
    #pinentry-curses (pinentry)
    VERSION_lower="${VERSION_lower//pinentry-curses\ (pinentry)/pinentry}"
    # lsusb (usbutils)
    VERSION_lower="${VERSION_lower//lsusb\ (usbutils)/usbutils}"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/nc\.traditional\ \[v\ /nc.traditional\ /g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/getconf\ (.*)/getconf/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/localedef\ (.*)/localedef/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/pt_chown\ (.*)/pt_chown/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/rpcinfo\ (.*)/rpcinfo/')"
    #This is perl 5, version 20, subversion 0 (v5.20.0) built
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/this\ is\ perl\ ([0-9]),\ ([0-9][0-9]),\ sub([0-9])/perl\ \1\.\2\.\3/')"
    # "****  XDB 70 Monitor V 0.9 (15.06.04), Copyright (C) SIEMENS AG 2004. All rights reserved. ****"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\*\*\*\*\ xdb\ 70\ monitor\ v\ ([0-9]\.[0-9]+).*/xdb_70_monitor\ \1/')"
    #"GNU\ gdb\ \(Debian\ [0-9]\.[0-9]+-[0-9]\)\ "
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/gnu\ gdb\ \(debian\ ([0-9]\.[0-9]+-[0-9]+\))\ /gdb\ \1/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/this\ is\ perl.*.v/perl\ /')"
    #gpg (GnuPG) 2.2.17
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/g.*\ (gnupg)/gnupg/')"
    #hostapd v2.0-devel
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/hostapd\ v([0-9]+\.[0-9]+)-devel/hostapd\ \1/g')"
    #wpa_supplicant v2.0-devel
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/wpa_supplicant\ v([0-9]+\.[0-9]+)-devel/wpa_supplicant\ \1/g')"
    #iw* Wireless-Tools version 29
    VERSION_lower="${VERSION_lower/wireless-tools/wireless_tools}"
    VERSION_lower="${VERSION_lower/iwconfig\ wireless_tools/wireless_tools}"
    # apt-Version 1.2.3
    VERSION_lower="${VERSION_lower//apt-/apt\ }"
    # remove the v in something like this: "space v[number]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ v([0-9]+)/\ \1/g')" 
    # "mkfs\.jffs2\ revision\ [0-9]\.[0-9]\.[0-9]\.[0-9]"
    VERSION_lower="${VERSION_lower//revision\ /}"
    # mkfs.jffs2: error!: revision 1.60
    VERSION_lower="${VERSION_lower//:\ error!:/}"
    #"Dropbear\ sshd\ v20[0-9][0-9]\.[0-9][0-9]"
    VERSION_lower="${VERSION_lower//dropbear\ sshd/dropbear_ssh}"
    #Dropbear multi-purpose version 2012.55
    VERSION_lower="${VERSION_lower//dropbear multi-purpose\ /dropbear\ }"
    #Dropbear v2016.74
    VERSION_lower="${VERSION_lower//dropbear\ /dropbear_ssh\ }"
    #3.0.10 - $Id: ez-ipupdate.c,v 1.44 (from binary 3322ip) found in qemu_3322ip.txt.
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/([0-9]\.[0-9]\.[0-9]+)\ -\ .*ez\-ipupdate\.c,v\ [0-9]\.[0-9][0-9]/ez-ipupdate \1/')"
    # blockman 0.0.1.blockman build-20151021
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/blockman\ ([0-9]\.[0-9]\.[0-9]+)\.blockman\ .*/blockman \1/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/flowman\ ([0-9]\.[0-9]\.[0-9]+)\.flowman\ .*/flowman \1/')"
    # ipset 6.30 protocol 6
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ipset\ ([0-9]\.[0-9]+)\ protocol\ [0-9]/ipset \1/')"
    # ozker 0.0.2.ozker build-20151021
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ozker\ ([0-9]\.[0-9]\.[0-9])\.ozker\ .*/ozker \1/')"
    # this is haserl 0.9.35 (http /haserl.sourceforge.net
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/this\ is\ haserl\ ([0-9]\.[0-9]\.[0-9]+)\ .*/haserl \1/')"
    #"ndisc6\:\ IPv6\ Neighbor\/Router\ Discovery\ userland\ tool\ [0-9]\.[0-9]\.[0-9]\ "
    VERSION_lower="${VERSION_lower//\:\ ipv6\ neighbor\/router\ discovery\ userland\ tool/}"
    #"ucloud_v2\ ver\.[0-9][0-9][0-9]"
    VERSION_lower="${VERSION_lower//ver\./}"
    # rdnssd\:\ IPv6\ Recursive\ DNS\ Server\ discovery\ Daemon\
    VERSION_lower="${VERSION_lower//\:\ ipv6\ recursive\ dns\ server\ discovery\ daemon/}"
    #NETIO\ -\ Network\ Throughput\ Benchmark,\ Version
    VERSION_lower="${VERSION_lower//-\ network\ throughput\ benchmark\,\ /}"
    #ntpd\ -\ NTP\ daemon\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//-\ ntp\ daemon\ program\ -/}"
    # GNU bash, 4.3.39
    VERSION_lower="${VERSION_lower//gnu\ bash,\ /bash\ }"
    # FUSE library version: 2.9.4
    VERSION_lower="${VERSION_lower//fuse\ library/fuse}"
    #Linux strongSwan 5.2.2 
    VERSION_lower="${VERSION_lower//linux\ strongswan/strongswan}"
    # NET-SNMP\ version:\ \ 
    #VERSION_lower="${VERSION_lower//net-snmp/net-snmp}"
    #igmpproxy, Version 0.1
    VERSION_lower="${VERSION_lower//,/}"
    #flash_eraseall $ 1.1 $
    VERSION_lower="${VERSION_lower//\$/}"
    VERSION_lower="${VERSION_lower//\"/}"
    #radlogin.cv
    VERSION_lower="${VERSION_lower//radlogin\.cv/radlogin}"
    #event log utility
    VERSION_lower="${VERSION_lower//event\ log\ utility/event_log_utility}"
    #message manager utility
    VERSION_lower="${VERSION_lower//message\ manager\ utility/message_manager_utility}"
    # BoosterMainFunction:305
    VERSION_lower="${VERSION_lower//boostermainfunction:305/booster}"
    VERSION_lower="${VERSION_lower//:/}"
    VERSION_lower="${VERSION_lower//--\ /}"
    VERSION_lower="${VERSION_lower//-\ /}"
    #glib-compile-schemas 2.50.3
    VERSION_lower="${VERSION_lower/glib-compile-schemas\ /gnome:glib\ }"
    #mtr mtr 0.85
    VERSION_lower="${VERSION_lower/mtr\ mtr/mtr:mtr}"
    VERSION_lower="${VERSION_lower/\//\ }"
    #OpenLDAP:\ ldapsearch
    VERSION_lower="${VERSION_lower/openldap\ ldapsearch/openldap}"
    #version: openser 1.0.0 (arm/linux)
    VERSION_lower="${VERSION_lower/version\ openser/openser:openser}"
    #Beceem\ CM\ Server\
    VERSION_lower="${VERSION_lower//beceem\ cm\ server/beceem}"
    VERSION_lower="${VERSION_lower//beceem\ cscm\ command\ line\ client/beceem}"
    # CLIENT\ libcurl\
    VERSION_lower="${VERSION_lower//client\ libcurl/libcurl}"
    #Intel SDK for UPnP devices /1.2
    VERSION_lower="${VERSION_lower//intel\ sdk\ for\ upnp\ devices\ \ /portable_sdk_for_upnp\ }"
    # busybox 1.00-pre2 -> we ignore the pre
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/busybox\ ([0-9]\.[0-9][0-9])-pre[0-9]/busybox\ \1/g')"
    # GNU C Library (AuDis-V04.56) stable release version 2.23
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/gnu\ c\ library\ .*\ release/glibc/')"
    # (Debian EGLIBC 2.13-38+deb7u11) 2.13
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(eglibc)/eglibc/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(.*\ eglibc\ .*)/eglibc/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(debian\ glibc.*)/glibc/')"
    #vxworks 7 sr0530 -> vxworks 7:sr0530
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/vxworks\ ([0-9])\ sr([0-9]+)/vxworks\ \1:sr\2/g')"
    #vxworks5.5.1 -> no space
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/vxworks([0-9]\.[0-9]+\.[0-9]+)/vxworks\ \1/g')"
    #VxWorks operating system version "5.5.1"
    VERSION_lower="${VERSION_lower//vxworks\ operating\ system/vxworks}"
    #OpenSSH_7.8p1 -> openssh 7.8:p1 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/openssh_([0-9])\.([0-9])([a-z][0-9])/openssh\ \1\.\2:\3/g')"
    #socat 2.0.0-b4 -> socat 2.0.0:b4 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/socat\ ([0-9]\.[0-9]\.[0-9])-([a-z][0-9])/socat\ \1:\2/g')"
    # pppd 2.4.2b3
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/pppd\ ([0-9]\.[0-9]\.[0-9])([a-z][0-9])/pppd\ \1:\2/g')"
    # ntpd 4.2.8p13 -> ntp 4.2.8:p13
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntp[dq]\ ([0-9]\.[0-9]\.[0-9])([a-z][0-9])/ntp\ \1:\2/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntpdc\ vendor-specific.*query.*([0-9]\.[0-9]\.[0-9])([a-z][0-9])/ntp\ \1:\2/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntpdc\ vendor-specific.*ntpd.*([0-9]\.[0-9]\.[0-9])([a-z][0-9]+)/ntp\ \1:\2/g')"
    #sntp 4.2.8p10@1.3728-o Mon Mar  9 18:03:45 UTC 2020 (1)
    VERSION_lower="${VERSION_lower/sntp\ /ntp\ }"
    # ntpdate 4.2.8p13 -> ntp 4.2.8:p13
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntpdate\ ([0-9]\.[0-9]\.[0-9])([a-z]([0-9]))/ntp\ \1:\2/g')"
    # ntp-keygen 4.2.8p10@1.3728-o Mon Mar  9 18:04:19 UTC 2020 (1)
    VERSION_lower="${VERSION_lower/ntp-keygen\ /ntp\ }"
    # FreeBSD 12.1-RELEASE-p8  -> FreeBSD 12.1:p8 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/freebsd\ ([0-9]+\.[0-9]+)-release-([a-z]([0-9]+))/freebsd\ \1:\2/g')"
    # unzip .... info-zip -> info-zip
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipinfo\ ([0-9]\.[0-9][0-9])\ .*\ info-zip.*/info-zip:zip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/unzip\ ([0-9]\.[0-9][0-9])\ .*\ by\ info-zip.*/info-zip:unzip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zip\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipcloak\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zipcloak\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipnote\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zipnote\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/([a-z]\ UnZip),/info-zip:zip/')"
    #ZipSplit 3.0
    VERSION_lower="${VERSION_lower/zipsplit\ /info-zip:zip\ }"
    #mdns repeater (1.10)
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/mdns\ repeater\ \(([0-9]\.[0-9][0-9])\)/mdnsrepeater\ \1/g')"
    #management console agent 1.5 (c) ubiquiti networks inc
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/management\ console\ agent\ ([0-9]\.[0-9]).*ubiquiti\ networks/ubiquiti:console_agent\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/multipurpose.*control\ daemon\ ([0-9]\.[0-9]).*ubiquiti/ubiquiti:control_daemon\ \1/g')"
    #avahi::"avahi-.*[0-9]\.[0-9]\.[0-9][0-9]$"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/avahi-.*\ ([0-9]\.[0-9]\.[0-9][0-9])/avahi\ \1/g')"
    #server debian wheezy upnp/1.1 miniupnpd/2.1
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/server.*upnp.*miniupnpd\/([0-9]\.[0-9])/miniupnpd\ \1/g')"
    #CONFIG_SET (/runtime/VerInfo/Web, 1.4b191) error! -> goahead
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/CONFIG_SET\ \(\/runtime\/VerInfo\/Web,\ ([0-9]\.[0-9]b[0-9]+)\)/goahead\ \1/g')"
    # linux -> kernel (we find the CVEs in the database with kernel as search string)
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^linux\ ([0-9])/kernel\ \1/')"
    # Siprotec 5 firmware has a version identifier like FWAOS_V01.11.01.123
    VERSION_lower="${VERSION_lower//fwaos_v/siprotec_5\ }"
    #@(#1) CP443-1 GX20 V x.y.z 11.11.9999
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\@\(\#1\)\ cp443-1\ gx20\ v\ ([0-9]\.[0-9]\.[0-9]).*/simatic_cp443-1_firmware \1/')"
    #  Firmware Update V3.2.17 for the communication processor CP443-1
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/firmware\ update\ ([0-9]\.[0-9]\.[0-9]+)\ for\ the\ communication\ processor\ cp443-1/simatic_cp443-1_firmware \1/')"
    #isc-dhclient-4.1-ESV-R8 -> isc:dhcp_client
    VERSION_lower="${VERSION_lower//isc-dhclient-/isc:dhcp_client\ }"
    VERSION_lower="${VERSION_lower//internet\ systems\ consortium\ dhcp\ client\ /isc:dhcp_client\ }"
    # DHCP Client Daemon v.1.3.22-pl4 -> it is phystech dhcpcd
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/dhcp\ client\ daemon\ v\.([0-9]\.[0-9]\.[0-9]+)-(pl[0-9])/phystech:dhcpcd \1_\2/')"
    VERSION_lower="${VERSION_lower//dhcp\ client\ daemon\ v\./phystech:dhcpcd\ }"
    #jq commandline json processor [5a49c82-dirty]
    #VERSION_lower="${VERSION_lower//jq\ commandline\ json\ processor\ \[/jq_project:jq\ }"
    #Squid\ Cache:\ Version\ [0-9]\.[0-9]\.[0-9]$"
    VERSION_lower="${VERSION_lower//squid\ cache/squid-cache:squid}"
    #tar (GNU tar) 1.23
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ tar)/gnu:tar/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ findutils)/gnu:findutils/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ groff)/gnu:groff/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ sed)/gnu:sed/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ mtools)/gnu:mtools/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ cpio)/gnu:cpio/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ texinfo)/gnu:texinfo/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ gettext-runtime)/gnu:gettext/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/gnu\ inetutils/gnu:inetutils/')"
    #ld-musl-armhf.so.1 -> musl-libc:musl
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/ld-musl-armhf.so.1/musl-libc:musl/')"
    # handle grub version 2:
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(grub)\ 2/grub2\ 2/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(grub)/grub/')"
    VERSION_lower="${VERSION_lower//gnu\ sed/gnu:sed}"
    VERSION_lower="${VERSION_lower//gnu\ make/gnu:make}"
    VERSION_lower="${VERSION_lower//gnu\ nano/gnu:nano}"
    VERSION_lower="${VERSION_lower//loadkeys\ von\ kbd/kbd-project:kbd}"
    VERSION_lower="${VERSION_lower//loadkeys\ from\ kbd/kbd-project:kbd}"
    VERSION_lower="${VERSION_lower//kbd_mode\ from\ kbd/kbd-project:kbd}"
    #dpkg-ABC -> dpkg
    VERSION_lower="${VERSION_lower//dpkg-divert/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-split/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-deb/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-trigger/debian:dpkg}"
    # sisco mms lite (MMS-LITE-80X-001)
    # we currently have no version data
    VERSION_lower="${VERSION_lower//mms-lite-80x-001/sisco:mms-lite}"
    # ncurses -> gnu:ncurses
    VERSION_lower="${VERSION_lower//ncurses/gnu:ncurses}"
    #VERSION_lower="${VERSION_lower//(gnu\ binutils.*)/gnu:binutils}"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ binutils.*)/gnu:binutils/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ grep.*)/gnu:grep/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ diffutils.*)/gnu:diffutils/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ coreutils.*)/gnu:coreutils/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ sharutils.*)/gnu:sharutils/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(xz\ utils.*)/xz-utils/')"
    #zend engine 2.4.0 copyright (c) 1998-2014 zend technologies
    VERSION_lower="${VERSION_lower//zend\ engine/zend:engine}"
    #D-Bus Message Bus Daemon 1.6.8
    VERSION_lower="${VERSION_lower//d-bus\ message\ bus\ daemon/freedesktop:dbus}"
    VERSION_lower="${VERSION_lower//d-bus\ socket\ cleanup\ utility/freedesktop:dbus}"
    VERSION_lower="${VERSION_lower//d-bus\ uuid\ generator/freedesktop:dbus}"
    #Roaring Penguin PPPoE Version
    VERSION_lower="${VERSION_lower//roaring\ penguin\ pppoe/roaring_penguin:pppoe}"
    #upnp controlpoint 1.0
    VERSION_lower="${VERSION_lower//upnp\ controlpoint/upnp_controlpoint}"
    #----welcome to realtek camera tool.
    VERSION_lower="${VERSION_lower//----welcome\ to\ realtek\ camera\ tool\./realtek_camera_tool}"
    #remove '
    VERSION_lower="${VERSION_lower//\'/}"
    # Ralink\ DOT1X\ daemon,\ version\ = '
    VERSION_lower="${VERSION_lower//ralink\ dot1x\ daemon\ \=\ /ralink-dot1x\ }"
    #his\ is\ WiFiDog\ 
    VERSION_lower="${VERSION_lower//this\ is\ wifidog/wifidog}"

    ### handle versions of linux distributions:
    # debian 9 (stretch) - installer build 20170615+deb9u5
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(debian) [0-9]+\ \([a-z]+\)\ installer\ build\ [0-9]+\+deb([0-9]+)u([0-9])/\1:\1_linux:\2\.\3/')"
    # Fedora 17 (Beefy Miracle)
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(fedora)\ ([0-9]+).*/\1project:\1:\2/')"
    # Ubuntu
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(ubuntu)\ ([0-9]+\,[0-9]+).*/\1_linux:\1:\2/')"
    # OpenWRT KAMIKAZE r18* -> 8.09.2
    # see also: https://openwrt.org/about/history
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(openwrt)\ (kamikaze)\ r1[4-8][0-9][0-9][0-9].*/\1:\2:8.09/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(openwrt)\ (backfire)\ r2[0-9][0-9][0-9][0-9].*/\1:\2:10.03/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/(openwrt)\ (lede)\ r3[2-9][0-9][0-9].*/\1:\2:17.01/')"
    # d-link dir-300 2.14b01
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/d-link\ (.*)\ ([0-9].[0-9]+[a-z][0-9]+)/dlink:\1_firmware:\2/')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/d-link\ (.*)\ ([0-9].[0-9]+)/dlink:\1_firmware:\2/')"

    if ! [[ "$VERSION_lower" == "dlink"* ]]; then
      # letz try to handle something like 1p2 -> 1:p2
      VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/([0-9])([a-z]([0-9]))/\1:\2/g')"
    fi

    # final cleanup of start and ending
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-git$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-beta$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^-//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^_//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/_$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^\ //')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ $//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\.$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\]$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/[)$]//')"
    #print_output "$VERSION_lower"

    # sometimes we get "Linux kernel x.yz.ab -> remove the first part of it
    if [[ $VERSION_lower == *linux\ kernel* ]]; then
      VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f2-3)"
    fi

    # now we should have the name and the version in the first two coloumns:
    VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f1-2)"

    # check if we have some number in it ... without a number we have no version info and we can drop this entry ...
    if [[ $VERSION_lower =~ [0-9] ]]; then
      # for multi threading we have to go via a temp file
      echo "$VERSION_lower" >> "$LOG_PATH_MODULE"/versions.tmp
    fi
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  # initial output - probably we will remove it in the future
  # currently it is very helpful
  if [[ ${#VERSIONS_BASE_CHECK[@]} -gt 0 || ${#VERSIONS_STAT_CHECK[@]} -gt 0 || ${#VERSIONS_EMULATOR[@]} -gt 0 || ${#VERSIONS_KERNEL[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR[@]} || ${#VERSIONS_S06_FW_DETAILS[@]} -gt 0 ]]; then
    print_output "[*] Software inventory initial overview:"
    write_anchor "softwareinventoryinitialoverview"
    for VERSION in "${VERSIONS_S06_FW_DETAILS[@]}"; do
      print_output "[+] Found Version details (firmware details check): ""$VERSION"
    done
    for VERSION in "${VERSIONS_BASE_CHECK[@]}"; do
      print_output "[+] Found Version details (base check): ""$VERSION"
    done
    for VERSION in "${VERSIONS_STAT_CHECK[@]}"; do
      print_output "[+] Found Version details (statical check): ""$VERSION"
    done
    for VERSION in "${VERSIONS_EMULATOR[@]}"; do
      print_output "[+] Found Version details (emulator): ""$VERSION"
    done
    for VERSION in "${VERSIONS_SYS_EMULATOR[@]}"; do
      print_output "[+] Found Version details (system emulator): ""$VERSION"
    done
    for VERSION in "${VERSIONS_KERNEL[@]}"; do
      print_output "[+] Found Version details (kernel): ""$VERSION"
    done

    print_output ""
    VERSIONS_AGGREGATED=("${VERSIONS_BASE_CHECK[@]}" "${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}" "${VERSIONS_SYS_EMULATOR[@]}" "${VERSIONS_S06_FW_DETAILS[@]}")
    for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
      # remove color codes:
      VERSION=$(echo "$VERSION" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      if [[ "$THREADED" -eq 1 ]]; then
        prepare_version_data &
        WAIT_PIDS_F19+=( "$!" )
      else
        prepare_version_data
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_F19[@]}"
    fi
  fi

  # sorting and unique our versions array:
  #eval "VERSIONS_CLEANED=($(for i in "${VERSIONS_CLEANED[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ -f "$LOG_PATH_MODULE"/versions.tmp ]]; then
    # on old kernels it takes a huge amount of time to query all kernel CVE's. So, we move the kernel entry to the begin of our versions array
    mapfile -t KERNELS < <(grep kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u)
    grep -v kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u > "$LOG_PATH_MODULE"/versions1.tmp
    for KERNEL in "${KERNELS[@]}"; do
      if [[ $( wc -l "$LOG_PATH_MODULE"/versions1.tmp | cut -d" " -f1 ) -eq 0 ]] ; then
        echo "$KERNEL" > "$LOG_PATH_MODULE"/versions1.tmp
      else
        sed -i "1s/^/$KERNEL\n/" "$LOG_PATH_MODULE"/versions1.tmp
      fi
    done
    mapfile -t VERSIONS_CLEANED < <(cat "$LOG_PATH_MODULE"/versions1.tmp)
    rm "$LOG_PATH_MODULE"/versions*.tmp 2>/dev/null

    # leave this here for debugging reasons
    #if [[ ${#VERSIONS_CLEANED[@]} -ne 0 ]]; then
    #  print_output "[*] Software inventory aggregated:"
    #  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    #    print_output "[+] Found Version details (aggregated): ""$VERSION"
    #  done
    #else
    #  print_output "[-] No Version details found."
    #fi
  else
    print_output "[-] No Version details found."
  fi
}

generate_special_log() {
  if [[ $(grep -c "Found.*CVEs\ and" "$LOG_FILE") -gt 0 ]]; then
    sub_module_title "Minimal report of exploits and CVE's."
    write_anchor "minimalreportofexploitsandcves"

    readarray -t FILES < <(find "$LOG_PATH_MODULE"/ -type f)
    print_output ""
    print_output "[*] CVE log file stored in $CVE_MINIMAL_LOG.\\n"
    for FILE in "${FILES[@]}"; do
      NAME=$(basename "$FILE" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      CVE_VALUES=$(grep ^CVE "$FILE" | cut -d: -f2 | tr -d '\n' | sed -r 's/[[:space:]]+/, /g' | sed -e 's/^,\ //') 
      if [[ -n $CVE_VALUES ]]; then
        print_output "[*] CVE details for ${GREEN}$NAME${NC}:\\n"
        print_output "$CVE_VALUES"
        echo -e "\n[*] CVE details for ${GREEN}$NAME${NC}:" >> "$CVE_MINIMAL_LOG"
        echo "$CVE_VALUES" >> "$CVE_MINIMAL_LOG"
        print_output ""
      fi
    done

    print_output ""
    print_output "[*] Minimal exploit summary file stored in $EXPLOIT_OVERVIEW_LOG.\\n"
    mapfile -t EXPLOITS_AVAIL < <(grep -E "Exploit\ \(" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r)
    for EXPLOIT_ in "${EXPLOITS_AVAIL[@]}"; do
      # remove color codes:
      EXPLOIT_=$(echo "$EXPLOIT_" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      CVSS_VALUE=$(echo "$EXPLOIT_" | sed -e 's/.*CVE-[0-9]//g' | cut -d: -f2 | sed -e 's/[[:blank:]]//g')
      if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
        print_output "$RED$EXPLOIT_$NC"
      elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
        print_output "$ORANGE$EXPLOIT_$NC"
      else
        print_output "$GREEN$EXPLOIT_$NC"
      fi
    done
    echo -e "\n[*] Exploit summary:" >> "$EXPLOIT_OVERVIEW_LOG"
    grep "Exploit\ available" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r >> "$EXPLOIT_OVERVIEW_LOG"
  fi
}

cve_db_lookup() {
  # using $VERSION variable:
  VERSION_SEARCH="${VERSION//\ /:}"
  VERSION_PATH="${VERSION//\ /_}"
  VERSION_BINARY=$(echo "$VERSION_SEARCH" | cut -d: -f1)
  print_output "[*] CVE database lookup with version information: ${GREEN}$VERSION_SEARCH${NC}" "" "f19#cve_$VERSION_BINARY"

  # CVE search:
  $PATH_CVE_SEARCH -p "$VERSION_SEARCH" > "$LOG_PATH_MODULE"/"$VERSION_PATH".txt

  if [[ "$VERSION_SEARCH" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    VERSION_SEARCHx="$(echo "$VERSION_SEARCH" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${GREEN}$VERSION_SEARCHx${NC}" "" "f19#cve_$VERSION_BINARY"
    $PATH_CVE_SEARCH -p "$VERSION_SEARCHx" >> "$LOG_PATH_MODULE"/"$VERSION_PATH".txt
  fi

  AGG_LOG_FILE="$VERSION_PATH".txt
  if [[ "$THREADED" -eq 1 ]]; then
    cve_extractor &
    WAIT_PIDS_F19_2+=( "$!" )
  else
    cve_extractor
  fi

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19_2[@]}"
  fi
}

cve_extractor() {
  EXPLOIT_COUNTER_VERSION=0
  CVE_COUNTER_VERSION=0
  # extract the CVE numbers and the CVSS values and sort it:
  readarray -t CVEs_OUTPUT < <(grep -A2 -e "[[:blank:]]:\ CVE-" "$LOG_PATH_MODULE"/"$AGG_LOG_FILE" | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)
  VERSION_SEARCH=$(echo "$AGG_LOG_FILE" | sed -e 's/.txt$//' | sed -e 's/_/:/g')

  for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
    ((CVE_COUNTER++))
    ((CVE_COUNTER_VERSION++))
    #extract the CVSS and CVE value (remove all spaces and tabs)
    CVSS_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f3 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    CVE_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')

    # default value
    EXPLOIT="No exploit available"

    EDB=0
    # as we already know about a buch of kernel exploits - lets search them first
    if [[ "$VERSION_BINARY" == *kernel* ]]; then
      for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
        if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_VALUE" ]]; then
          EXPLOIT="Exploit (linux-exploit-suggester"
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
          EDB=1
        fi
      done
    fi

    if [[ "$CVE_SEARCHSPLOIT" -eq 1 || "$MSF_SEARCH" -eq 1 ]] ; then
      if [[ $CVE_SEARCHSPLOIT -eq 1 ]]; then
        mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "$CVE_VALUE" 2>/dev/null)
      fi

      if [[ $MSF_SEARCH -eq 1 ]]; then
        mapfile -t EXPLOIT_AVAIL_MSF < <(grep "$CVE_VALUE" "$MSF_DB_PATH" 2>/dev/null)
      fi

      if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
        readarray -t EXPLOIT_IDS < <(echo "${EXPLOIT_AVAIL[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //')
        if [[ "$EXPLOIT" == "No exploit available" ]]; then
          EXPLOIT="Exploit (EDB ID:"
        else
          EXPLOIT="$EXPLOIT"" / EDB ID:"
        fi
        for EXPLOIT_ID in "${EXPLOIT_IDS[@]}" ; do
          EXPLOIT="$EXPLOIT"" ""$EXPLOIT_ID"
          echo -e "[+] Exploit for $CVE_VALUE:\\n" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
          for LINE in "${EXPLOIT_AVAIL[@]}"; do
            echo "$LINE" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
          done
          EDB=1
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
        done
        readarray -t EXPLOIT_FILES < <(echo "${EXPLOIT_AVAIL[@]}" | grep "File:" | cut -d ":" -f 2 | sed 's/\ //')
        for E_FILE in "${EXPLOIT_FILES[@]}"; do
          if [[ -f "$E_FILE" ]] ; then
            cp "$E_FILE" "$LOG_PATH_MODULE""/exploit/edb_""$(basename "$E_FILE")"
          fi
        done
      fi

      if [[ ${#EXPLOIT_AVAIL_MSF[@]} -gt 0 ]]; then
        if [[ "$EXPLOIT" == "No exploit available" ]]; then
          EXPLOIT="Exploit (MSF:"
        else
          EXPLOIT="$EXPLOIT"" ""/ MSF:"
        fi
        for EXPLOIT_MSF in "${EXPLOIT_AVAIL_MSF[@]}" ; do
          EXPLOIT_PATH=$(echo "$EXPLOIT_MSF" | cut -d: -f1)
          EXPLOIT_NAME=$(basename -s .rb "$EXPLOIT_PATH")
          EXPLOIT="$EXPLOIT"" ""$EXPLOIT_NAME"
          if [[ -f "$EXPLOIT_PATH" ]] ; then
            # for the web reporter we copy the original metasploit module into the emba log directory
            cp "$EXPLOIT_PATH" "$LOG_PATH_MODULE""/exploit/msf_""$EXPLOIT_NAME".rb
          fi
          ((MSF_MODULE_CNT++))
        done
        if [[ $EDB -eq 0 ]]; then
          # only count the msf exploit if we have not already count an EDB exploit
          # otherwise we count an exploit for one CVE twice
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
          EDB=1
        fi
      fi
    fi
    if [[ $EDB -eq 1 ]]; then
      EXPLOIT="$EXPLOIT"")"
    fi

    CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$VERSION_SEARCH""/" | sed -e 's/\ \+/\t/g')
    BINARY=$(echo "$CVE_OUTPUT" | cut -d: -f1 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    VERSION=$(echo "$CVE_OUTPUT" | cut -d: -f2- | sed -e 's/\t//g' | sed -e 's/\ \+//g' | sed -e 's/:CVE-[0-9].*//')
    # we do not deal with output formatting the usual way -> we use printf
    if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${RED}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((HIGH_CVE_COUNTER++))
    elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${ORANGE}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((MEDIUM_CVE_COUNTER++))
    else
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${GREEN}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((LOW_CVE_COUNTER++))
    fi
  done


  { echo ""
    echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$VERSION_SEARCH"
  } >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
  if [[ $LOW_CVE_COUNTER -gt 0 ]]; then
    echo "$LOW_CVE_COUNTER" >> "$TMP_DIR"/LOW_CVE_COUNTER.tmp
  fi
  if [[ $MEDIUM_CVE_COUNTER -gt 0 ]]; then
    echo "$MEDIUM_CVE_COUNTER" >> "$TMP_DIR"/MEDIUM_CVE_COUNTER.tmp
  fi
  if [[ $HIGH_CVE_COUNTER -gt 0 ]]; then
    echo "$HIGH_CVE_COUNTER" >> "$TMP_DIR"/HIGH_CVE_COUNTER.tmp
  fi
  if [[ $EXPLOIT_COUNTER -gt 0 ]]; then
    echo "$EXPLOIT_COUNTER" >> "$TMP_DIR"/EXPLOIT_COUNTER.tmp
  fi
  if [[ $MSF_MODULE_CNT -gt 0 ]]; then
    echo "$MSF_MODULE_CNT" >> "$TMP_DIR"/MSF_MODULE_CNT.tmp
  fi

  if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    write_anchor "cve_$BINARY"
    print_output ""
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $RED$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $RED$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION.${NC}"
    print_output ""
  elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]]; then
    write_anchor "cve_$BINARY"
    print_output ""
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $ORANGE$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $ORANGE$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION.${NC}"
    print_output ""
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE and exploit details."
  write_anchor "collectcveandexploitdetails"

  CVE_COUNTER=0
  EXPLOIT_COUNTER=0


  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    if [[ "$THREADED" -eq 1 ]]; then
      # cve-search/mongodb calls called in parallel
      cve_db_lookup &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$MAX_MODS" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi

  mapfile -t LOG_AGGR_FILES < <(find "$LOG_PATH_MODULE"/cve_sum/ -type f -name "*.txt" | sort 2> /dev/null)
  if [[ ${#LOG_AGGR_FILES[@]} -gt 0 ]]; then
    print_output ""
    print_output "[*] Identified the following version details, vulnerabilities and exploits:"
    for FILE_AGGR in "${LOG_AGGR_FILES[@]}"; do
      if [[ "$THREADED" -eq 1 ]]; then
        final_outputter &
        WAIT_PIDS_F19+=( "$!" )
      else
        final_outputter
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_F19[@]}"
    fi
    print_output "${NC}"
  fi
}

final_outputter() {
    if [[ -f $FILE_AGGR ]]; then
      BIN=""
      VERSION=""
      STATS=$(grep "\[+\]\ Statistics\:" "$FILE_AGGR" | cut -d: -f2- 2>/dev/null)
      #26|0|gnu:binutils:2.21:p12
  
      BIN_VERSION=$(echo "$STATS" | cut -d\| -f3-)
      # shellcheck disable=SC2001
      BIN_VERSION=$(echo "$BIN_VERSION" | sed -e 's/:/\ /g')
      #gnu:binutils:2.21:p12

      F_COUNTER=0
      for FIELD in $BIN_VERSION; do

        if [[ "$F_COUNTER" -eq 0 ]];then
          # the initial field is always the binary name
          BIN="$FIELD"
        elif echo "$FIELD" | grep -q "^p[0-9]"; then
          # something like "binary 1.23 p13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^r[0-9]"; then
          # something like "binary 1.23 r13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^b[0-9]"; then
          # something like "binary 1.23 b13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^sr[0-9][0-9][0-9][0-9]"; then
          #VxWorks:sr0530
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^[a-z]"; then
          # if FIELD starts with a letter it is a binary name
          # cases like r12 and p12 are already handled as versions
          BIN="$BIN $FIELD"
        elif echo "$FIELD" | grep -q "^[0-9]"; then
          VERSION="$VERSION $FIELD"
        elif [[ "$F_COUNTER" -gt 2 ]];then
          # if we reach this and our counter is above 2 it is probably a version field
          VERSION="$VERSION-$FIELD"
        fi
        # sometimes we start with a space
        # shellcheck disable=SC2001
        VERSION=$(echo "$VERSION" | sed -e 's/^\ //')
        # shellcheck disable=SC2001
        BIN=$(echo "$BIN" | sed -e 's/^\ //' | sed -e 's/firmware//')
        if [[ "$BIN" == *"debian debian"* ]]; then
          BIN=$(echo "$BIN" | sed -e 's/debian\ debian/debian/')
        fi
        (( F_COUNTER++ ))
      done
  
      EXPLOITS=$(echo "$STATS" | cut -d\| -f2 | sed -e 's/\ //g')
      CVEs=$(echo "$STATS" | cut -d\| -f1 | sed -e 's/\ //g')
  
      if [[ -n "$CVEs" && -n "$EXPLOITS" ]]; then
        if [[ "$CVEs" -gt 0 || "$EXPLOITS" -gt 0 ]]; then
          if [[ "$EXPLOITS" -gt 0 ]]; then
            printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
          else
            printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
          fi
        elif [[ "$CVEs" -eq 0 && "$EXPLOITS" -eq 0 ]]; then
          printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
        else
          # this should never happen ...
          printf "[+] Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
        fi
      fi
    fi
}

get_firmware_base_version_check() {
  print_output "[*] Collect version details of module s09_firmware_base_version_check."
  if [[ -f "$LOG_DIR"/"$FW_VER_CHECK_LOG" ]]; then
    # if we have already kernel information:
    if [[ "$KERNELV" -eq 1 ]]; then
      # do not name a path to your firmware with "Linux-*" or "Linux kernel*"
      readarray -t VERSIONS_STAT_CHECK < <(grep "Version information found" "$LOG_DIR"/"$FW_VER_CHECK_LOG" | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u | grep -v "Linux kernel\|Linux-")
    else
      readarray -t VERSIONS_STAT_CHECK < <(grep "Version information found" "$LOG_DIR"/"$FW_VER_CHECK_LOG" | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u)
    fi
  fi
}

get_kernel_check() {
  print_output "[*] Collect version details of module s25_kernel_check."
  if [[ -f "$LOG_DIR"/"$KERNEL_CHECK_LOG" ]]; then
    readarray -t KERNEL_CVE_EXPLOITS < <(grep "\[+\].*\[CVE-" "$LOG_DIR"/"$KERNEL_CHECK_LOG" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | cut -d\[ -f3 | cut -d\] -f1 | sed -e 's/,/\r\n/g')
    ## do a bit of sed modifications to have the same output as from the pre checker
    readarray -t VERSIONS_KERNEL < <(grep "Statistics:" "$LOG_DIR"/"$KERNEL_CHECK_LOG" | sed -e 's/\[\*\]\ Statistics\:/kernel\ /' | sort -u)
  fi
}

get_usermode_emulator() {
  print_output "[*] Collect version details of module s115_usermode_emulator."
  if [[ -f "$LOG_DIR"/"$EMUL_LOG" ]]; then
    readarray -t VERSIONS_EMULATOR < <(grep "Version information found" "$LOG_DIR"/"$EMUL_LOG" | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (from.*$//' | sort -u)
  fi
}

get_systemmode_emulator() {
  print_output "[*] Collect version details of module l15_emulated_checks_init."
  if [[ -f "$LOG_DIR"/"$SYS_EMUL_LOG" ]]; then
    readarray -t VERSIONS_SYS_EMULATOR < <(grep "Version information found" "$LOG_DIR"/"$SYS_EMUL_LOG" | cut -d\  -f5- | sed 's/ in .* scanning logs.//' | sort -u)
  fi
}

get_firmware_details() {
  print_output "[*] Collect version details of module s06_distribution_identification."
  if [[ -f "$LOG_DIR"/"$S06_LOG" ]]; then
    readarray -t VERSIONS_S06_FW_DETAILS < <(grep "Version information found" "$LOG_DIR"/"$S06_LOG" | cut -d\  -f5- | sed 's/ in file .*//' | sort -u)
  fi
}
