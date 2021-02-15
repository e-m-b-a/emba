FROM kalilinux/kali-rolling

RUN apt-get update && \ 
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo

WORKDIR /app
ADD . /app

RUN yes | sudo ./installer.sh -D -F

ENTRYPOINT [ "/bin/bash" ]

