FROM kalilinux/kali-rolling

RUN apt-get update && \ 
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps

WORKDIR /app
ADD . /app

RUN yes | ./installer.sh

ENTRYPOINT [ "/bin/bash" ]

