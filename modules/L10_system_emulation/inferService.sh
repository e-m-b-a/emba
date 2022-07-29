# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022, Siemens Energy AG

# shellcheck disable=SC2148
BUSYBOX="/busybox"

ORANGE="\033[0;33m"
NC="\033[0m"

# This script is based on the original FirmAE inferFile.sh script 
# This script supports multiple startup services, colored output
# and more services

${BUSYBOX} echo "[*] EMBA inferService script starting ..."

${BUSYBOX} echo "[*] Service detection running ..."

if [ -e /etc/init.d/miniupnpd ]; then
  if ! ${BUSYBOX} grep -q "/etc/init.d/miniupnpd" /firmadyne/service 2>/dev/null; then
    ${BUSYBOX} echo -e "[*] Writing EMBA service for ${ORANGE}miniupnpd service${NC}"
    ${BUSYBOX} echo -e -n "/etc/init.d/miniupnpd start\n" >> /firmadyne/service
  fi
fi

if [ -e /etc/init.d/lighttpd ]; then
  if ! ${BUSYBOX} grep -q "/etc/init.d/lighttpd" /firmadyne/service 2>/dev/null; then
    ${BUSYBOX} echo -e "[*] Writing EMBA service for ${ORANGE}lighttpd service${NC}"
    ${BUSYBOX} echo -e -n "/etc/init.d/lighttpd start\n" >> /firmadyne/service
  fi
fi

# tplink_latest/Archer_C59_US__V2_161206.zip?
if [ -e /etc/init.d/uhttpd ]; then
  if ! ${BUSYBOX} grep -q uhttpd /firmadyne/service 2>/dev/null; then
    ${BUSYBOX} echo -e "[*] Writing EMBA service for ${ORANGE}uhttpd service${NC}"
    ${BUSYBOX} echo -e -n "/etc/init.d/uhttpd start\n" >> /firmadyne/service
  fi
fi

# FW_EA9400_1.0.3.181249_prod.img
if [ -e /etc/init.d/service_httpd.sh ]; then
  if ! ${BUSYBOX} grep -q service_httpd.sh /firmadyne/service 2>/dev/null; then
    ${BUSYBOX} echo -e "[*] Writing EMBA service for ${ORANGE}httpd service${NC}"
    ${BUSYBOX} echo -e -n "/etc/init.d/service_httpd.sh httpd-start\n" >> /firmadyne/service
  fi
fi
if [ -e /bin/boa ]; then
  if ! ${BUSYBOX} grep -q boa /firmadyne/service 2>/dev/null; then
    ${BUSYBOX} echo -e "[*] Writing EMBA service for ${ORANGE}/bin/boa${NC}"
    ${BUSYBOX} echo -e -n "/bin/boa\n" >> /firmadyne/service
  fi
fi

# Some examples for testing:
# mini_httpd: F9K1119_WW_1.00.01.bin
# twonkystarter: F9K1119_WW_1.00.01.bin

for BINARY in $(${BUSYBOX} find / -name "lighttpd" -type f -o -name "upnp" -type f -o -name "upnpd" -type f \
  -o -name "telnetd" -type f -o -name "mini_httpd" -type f -o -name "miniupnpd" -type f -o -name "twonkystarter" -type f \
  -o -name "httpd" -type f -o -name "goahead" -type f -o -name "alphapd" -type f -o -name "uhttpd" -type f -o -name "miniigd" -type f \
  -o -name "ISS.exe" -type f -o -name "ubusd" -type f); do
  if [ -x "${BINARY}" ]; then
    SERVICE_NAME=$(${BUSYBOX} basename "${BINARY}")
    # entry for lighttpd:
    if [ "$(${BUSYBOX} echo "${SERVICE_NAME}")" == "lighttpd" ]; then
      # check if this service is already in the service file:
      if ! ${BUSYBOX} grep -q "${SERVICE_NAME}" /firmadyne/service 2>/dev/null; then
        # check if we have a configuration available and iterate
        for LIGHT_CONFIG in $(${BUSYBOX} find / -name "lighttpd.conf" -type f); do
          # write the service starter with config file
          ${BUSYBOX} echo -e "[*] Writing EMBA service for $ORANGE${BINARY} - ${LIGHT_CONFIG}$NC"
          ${BUSYBOX} echo -e -n "${BINARY} -f ${LIGHT_CONFIG}\n" >> /firmadyne/service
        done
      fi
    elif [ "$(${BUSYBOX} echo "${SERVICE_NAME}")" == "miniupnpd" ]; then
      if ! ${BUSYBOX} grep -q "${SERVICE_NAME}" /firmadyne/service 2>/dev/null; then
        for MINIUPNPD_CONFIG in $(${BUSYBOX} find / -name "miniupnpd.conf" -type f); do
          ${BUSYBOX} echo -e "[*] Writing EMBA service for $ORANGE${BINARY} - ${MINIUPNPD_CONFIG}$NC"
          ${BUSYBOX} echo -e -n "${BINARY} -f ${MINIUPNPD_CONFIG}\n" >> /firmadyne/service
        done
      fi
    fi
    # this is the default case - without config but only if the service is not already in the service file
    if ! ${BUSYBOX} grep -q "${SERVICE_NAME}" /firmadyne/service 2>/dev/null; then
      ${BUSYBOX} echo -e "[*] Writing EMBA service for $ORANGE${BINARY}$NC"
      ${BUSYBOX} echo -e -n "${BINARY}\n" >> /firmadyne/service
    fi

    # other rules we need to apply
    if [ "$(${BUSYBOX} echo "${SERVICE_NAME}")" == "twonkystarter" ]; then
      ${BUSYBOX} mkdir -p /var/twonky/twonkyserver
    fi
  fi
done

${BUSYBOX} echo "[*] EMBA inferService script finished ..."
