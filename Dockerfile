FROM kalilinux/kali-rolling

RUN apt-get update && \ 
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo apt-utils

ADD ./installer.sh /

WORKDIR /

RUN yes | sudo /installer.sh -D -F

WORKDIR /emba

ENTRYPOINT [ "/bin/bash" ]

