FROM kalilinux/kali-rolling

RUN apt-get update && \ 
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo build-essential liblzma-dev liblzo2-dev zlib1g-dev git

WORKDIR /app
ADD . /app

RUN yes | ./installer.sh

RUN cd ./external/cve-search/ && \
    pip3 install -r requirements.txt && \
    xargs sudo apt-get install -y < requirements.system

ENTRYPOINT [ "/bin/bash" ]
