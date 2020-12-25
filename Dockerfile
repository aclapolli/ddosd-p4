# "Offloading Real-time DDoS Attack Detection to Programmable Data Planes" (IM 2019)
# Copyright (C) 2019  Ângelo Lapolli
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

FROM ubuntu:16.04 AS builder
WORKDIR /app
RUN apt update && apt install -y git
RUN git clone --recursive https://github.com/aclapolli/behavioral-model.git
RUN apt install -y lsb-release sudo
RUN cd behavioral-model && ./install_deps.sh 
RUN cd behavioral-model && ./autogen.sh && ./configure && make && make install
RUN git clone -b v3.2.0 --recursive https://github.com/protocolbuffers/protobuf.git
RUN apt install -y curl unzip
RUN cd protobuf && ./autogen.sh && ./configure && make && make install && ldconfig
RUN git clone --recursive https://github.com/aclapolli/p4c.git
RUN apt install -y libboost-iostreams-dev libgc-dev llvm-3.9
RUN cd p4c && mkdir build && cd build && cmake .. && make && make install

FROM ubuntu:16.04
WORKDIR /app
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/share/p4c /usr/local/share/p4c
COPY --from=builder /usr/lib/x86_64-linux-gnu/libnanomsg.so.1.0.0 /usr/lib/x86_64-linux-gnu/
RUN ln -s /usr/lib/x86_64-linux-gnu/libnanomsg.so.1.0.0 /usr/lib/x86_64-linux-gnu/libnanomsg.so.5.0.0 && ln -s /usr/lib/x86_64-linux-gnu/libnanomsg.so.5.0.0 /usr/lib/x86_64-linux-gnu/libnanomsg.so
RUN apt update && apt install -y ethtool gcc libboost-filesystem-dev libboost-iostreams-dev libboost-program-options-dev libboost-system-dev libboost-thread-dev libgc1c2 libgmp-dev libjudy-dev make python iproute2 tcpdump tcpreplay
COPY . .
RUN make
RUN chmod +x ./scripts/*
CMD ["./scripts/run.sh"]
