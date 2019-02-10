#ifndef HEADERS_P4
#define HEADERS_P4

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

// EtherType 0x6605
header ddosd_t {
    bit<32> pkt_num;
    bit<32> src_entropy;
    bit<32> src_ewma;
    bit<32> src_ewmmd;
    bit<32> dst_entropy;
    bit<32> dst_ewma;
    bit<32> dst_ewmmd;
    bit<8> alarm;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct headers {
    ethernet_t ethernet;
    ddosd_t ddosd;
    ipv4_t ipv4;
}

struct metadata {
    int<32> ip_count;
    bit<32> entropy_term;
    bit<32> pkt_num;
    bit<32> src_entropy;
    bit<32> src_ewma;
    bit<32> src_ewmmd;
    bit<32> dst_entropy;
    bit<32> dst_ewma;
    bit<32> dst_ewmmd;
    bit<8> alarm;
}

#endif /* HEADERS_P4 */
