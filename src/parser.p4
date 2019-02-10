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
