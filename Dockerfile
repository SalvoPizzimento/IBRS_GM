FROM ubuntu:latest

RUN apt update
RUN apt install -y make nano git iputils-ping net-tools wget gcc flex bison libgmp3-dev nettle-dev openssh-server

RUN wget "https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz"
RUN tar xzf pbc-0.5.14.tar.gz
RUN cd pbc-0.5.14 && ./configure && make && make install
RUN ldconfig -v

RUN cd /home && git clone https://github.com/SalvoPizzimento/IBRS_GM
