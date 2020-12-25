/*
 * "Offloading Real-time DDoS Attack Detection to Programmable Data Planes" (IM 2019)
 * Copyright (C) 2019  Ângelo Lapolli
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PARSER_P4
#define PARSER_P4

#include "headers.p4"

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_DDOSD 0x6605

parser ParserImpl(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_DDOSD: parse_ddosd;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ddosd {
        pkt.extract(hdr.ddosd);
        transition select(hdr.ddosd.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

#endif /* PARSER_P4 */
