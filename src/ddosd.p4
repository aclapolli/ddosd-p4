#include <v1model.p4>

#include "parser.p4"

#define CPU_SESSION 250
#define CS_WIDTH 976

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, hdr.ipv4.hdr_checksum, HashAlgorithm.csum16);
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Observation Window Parameters
    register<bit<5>>(1) log2_m;

    // Observation Window Control
    register<bit<32>>(1) training_len;
    register<bit<32>>(1) ow_counter;
    register<bit<32>>(1) packet_counter;

    // Count Sketch Counters
    register<int<32>>(CS_WIDTH) src_cs1;
    register<int<32>>(CS_WIDTH) src_cs2;
    register<int<32>>(CS_WIDTH) src_cs3;
    register<int<32>>(CS_WIDTH) src_cs4;
    register<int<32>>(CS_WIDTH) dst_cs1;
    register<int<32>>(CS_WIDTH) dst_cs2;
    register<int<32>>(CS_WIDTH) dst_cs3;
    register<int<32>>(CS_WIDTH) dst_cs4;

    // Count Sketch Counters Observation Window Annotation
    register<bit<8>>(CS_WIDTH) src_cs1_ow;
    register<bit<8>>(CS_WIDTH) src_cs2_ow;
    register<bit<8>>(CS_WIDTH) src_cs3_ow;
    register<bit<8>>(CS_WIDTH) src_cs4_ow;
    register<bit<8>>(CS_WIDTH) dst_cs1_ow;
    register<bit<8>>(CS_WIDTH) dst_cs2_ow;
    register<bit<8>>(CS_WIDTH) dst_cs3_ow;
    register<bit<8>>(CS_WIDTH) dst_cs4_ow;

    // Entropy Norms - Fixed point representation: 28 integer bits, 4 decimal bits.
    register<bit<32>>(1) src_S;
    register<bit<32>>(1) dst_S;

    // Entropy EWMA and EWMMD - Fixed point representation: 14 integer bits, 18 decimal bits.
    register<bit<32>>(1) src_ewma;
    register<bit<32>>(1) src_ewmmd;
    register<bit<32>>(1) dst_ewma;
    register<bit<32>>(1) dst_ewmmd;

    // Smoothing and Sensitivity Coefficients
    register<bit<8>>(1) alpha;    // Fixed point representation: 0 integer bits, 8 decimal bits.
    register<bit<8>>(1) k;        // Fixed point representation: 5 integer bits, 3 decimal bits.

    action drop() {
        mark_to_drop();
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table ipv4_fib {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }

    action get_entropy_term(bit<32> entropy_term) {
        meta.entropy_term = entropy_term;
    }

    // The two tables below are supposed to be implemented as a single one,
    // but our target (i.e., the simple_switch) does not support two table lookups within the the same control flow.
    table src_entropy_term {
        key = {
            meta.ip_count: lpm;
        }
        actions = {
            get_entropy_term;
        }
        default_action = get_entropy_term(0);
    }

    table dst_entropy_term {
        key = {
            meta.ip_count: lpm;
        }
        actions = {
            get_entropy_term;
        }
        default_action = get_entropy_term(0);
    }

    action cs_hash(in bit<32> ipv4_addr, out bit<32> h1, out bit<32> h2, out bit<32> h3, out bit<32> h4) {
        hash(h1, HashAlgorithm.hash1, 32w0, {ipv4_addr}, 32w4294967295);
        hash(h2, HashAlgorithm.hash2, 32w0, {ipv4_addr}, 32w4294967295);
        hash(h3, HashAlgorithm.hash3, 32w0, {ipv4_addr}, 32w4294967295);
        hash(h4, HashAlgorithm.hash4, 32w0, {ipv4_addr}, 32w4294967295);
    }

    action cs_ghash(in bit<32> ipv4_addr, out int<32> g1, out int<32> g2, out int<32> g3, out int<32> g4) {
        hash(g1, HashAlgorithm.ghash1, 32w0, {ipv4_addr}, 32w4294967295);
        hash(g2, HashAlgorithm.ghash2, 32w0, {ipv4_addr}, 32w4294967295);
        hash(g3, HashAlgorithm.ghash3, 32w0, {ipv4_addr}, 32w4294967295);
        hash(g4, HashAlgorithm.ghash4, 32w0, {ipv4_addr}, 32w4294967295);

        // As ghash outputs 0 or 1, we must map 0 to -1.
        g1 = 2*g1 - 1;
        g2 = 2*g2 - 1;
        g3 = 2*g3 - 1;
        g4 = 2*g4 - 1;
    }

    action median(in int<32> x1, in int<32> x2, in int<32> x3, in int<32> x4, out int<32> y) {
        // This is why we should minimize the sketch depth: the median operator is hardcoded.
        if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x2 >= x3 && x2 >= x4) || (x2 <= x1 && x2 <= x3 && x2 <= x4 && x1 >= x3 && x1 >= x4))
            y = (x3 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x3 >= x2 && x3 >= x4) || (x3 <= x1 && x3 <= x2 && x3 <= x4 && x1 >= x2 && x1 >= x4))
            y = (x2 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x4 >= x2 && x4 >= x3) || (x4 <= x1 && x4 <= x2 && x4 <= x3 && x1 >= x2 && x1 >= x3))
            y = (x2 + x3) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x3 >= x1 && x3 >= x4) || (x3 <= x1 && x3 <= x2 && x3 <= x4 && x2 >= x1 && x2 >= x4))
            y = (x1 + x4) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x4 >= x1 && x4 >= x3) || (x4 <= x1 && x4 <= x2 && x4 <= x3 && x2 >= x1 && x2 >= x3))
            y = (x1 + x3) >> 1;
        else
            y = (x1 + x2) >> 1;
    }

    apply {
        if (hdr.ipv4.isValid()) {

            // Current Observation Window
            bit<32> current_ow;
            ow_counter.read(current_ow, 0);


            // Source IP Address Frequency Estimation

            bit<32> src_h1;
            bit<32> src_h2;
            bit<32> src_h3;
            bit<32> src_h4;
            cs_hash(hdr.ipv4.src_addr, src_h1, src_h2, src_h3, src_h4);

            int<32> src_g1;
            int<32> src_g2;
            int<32> src_g3;
            int<32> src_g4;
            cs_ghash(hdr.ipv4.src_addr, src_g1, src_g2, src_g3, src_g4);

            // Row 1 Estimate

            bit<8> src_cs1_ow_aux;
            src_cs1_ow.read(src_cs1_ow_aux, src_h1);

            int<32> src_c1;
            if (src_cs1_ow_aux != current_ow[7:0]) {
                src_c1 = 0;
                src_cs1_ow.write(src_h1, current_ow[7:0]);
            } else {
                src_cs1.read(src_c1, src_h1);
            }
            src_c1 = src_c1 + src_g1;
            src_cs1.write(src_h1, src_c1);

            src_c1 = src_g1*src_c1;

            // Row 2 Estimate

            bit<8> src_cs2_ow_aux;
            src_cs2_ow.read(src_cs2_ow_aux, src_h2);

            int<32> src_c2;
            if (src_cs2_ow_aux != current_ow[7:0]) {
                src_c2 = 0;
                src_cs2_ow.write(src_h2, current_ow[7:0]);
            } else {
                src_cs2.read(src_c2, src_h2);
            }
            src_c2 = src_c2 + src_g2;
            src_cs2.write(src_h2, src_c2);

            src_c2 = src_g2*src_c2;

            // Row 3 Estimate

            bit<8> src_cs3_ow_aux;
            src_cs3_ow.read(src_cs3_ow_aux, src_h3);

            int<32> src_c3;
            if (src_cs3_ow_aux != current_ow[7:0]) {
                src_c3 = 0;
                src_cs3_ow.write(src_h3, current_ow[7:0]);
            } else {
                src_cs3.read(src_c3, src_h3);
            }
            src_c3 = src_c3 + src_g3;
            src_cs3.write(src_h3, src_c3);

            src_c3 = src_g3*src_c3;

            // Row 4 Estimate

            bit<8> src_cs4_ow_aux;
            src_cs4_ow.read(src_cs4_ow_aux, src_h4);

            int<32> src_c4;
            if (src_cs4_ow_aux != current_ow[7:0]) {
                src_c4 = 0;
                src_cs4_ow.write(src_h4, current_ow[7:0]);
            } else {
                src_cs4.read(src_c4, src_h4);
            }
            src_c4 = src_c4 + src_g4;
            src_cs4.write(src_h4, src_c4);

            src_c4 = src_g4*src_c4;

            // Count Sketch Source IP Frequency Estimate
            median(src_c1, src_c2, src_c3, src_c4, meta.ip_count);

            // LPM Table Lookup
            if (meta.ip_count > 0)
                src_entropy_term.apply();
            else
                meta.entropy_term = 0;

            // Source Entropy Norm Update
            bit<32> src_S_aux;
            src_S.read(src_S_aux, 0);
            src_S_aux = src_S_aux + meta.entropy_term;
            src_S.write(0, src_S_aux);


            // Destination IP Address Frequency Estimation

            bit<32> dst_h1;
            bit<32> dst_h2;
            bit<32> dst_h3;
            bit<32> dst_h4;
            cs_hash(hdr.ipv4.dst_addr, dst_h1, dst_h2, dst_h3, dst_h4);

            int<32> dst_g1;
            int<32> dst_g2;
            int<32> dst_g3;
            int<32> dst_g4;
            cs_ghash(hdr.ipv4.dst_addr, dst_g1, dst_g2, dst_g3, dst_g4);

            // Row 1 Estimate

            bit<8> dst_cs1_ow_aux;
            dst_cs1_ow.read(dst_cs1_ow_aux, dst_h1);

            int<32> dst_c1;
            if (dst_cs1_ow_aux != current_ow[7:0]) {
                dst_c1 = 0;
                dst_cs1_ow.write(dst_h1, current_ow[7:0]);
            } else {
                dst_cs1.read(dst_c1, dst_h1);
            }
            dst_c1 = dst_c1 + dst_g1;
            dst_cs1.write(dst_h1, dst_c1);

            dst_c1 = dst_g1*dst_c1;

            // Row 2 Estimate

            bit<8> dst_cs2_ow_aux;
            dst_cs2_ow.read(dst_cs2_ow_aux, dst_h2);

            int<32> dst_c2;
            if (dst_cs2_ow_aux != current_ow[7:0]) {
                dst_c2 = 0;
                dst_cs2_ow.write(dst_h2, current_ow[7:0]);
            } else {
                dst_cs2.read(dst_c2, dst_h2);
            }
            dst_c2 = dst_c2 + dst_g2;
            dst_cs2.write(dst_h2, dst_c2);

            dst_c2 = dst_g2*dst_c2;

            // Row 3 Estimate

            bit<8> dst_cs3_ow_aux;
            dst_cs3_ow.read(dst_cs3_ow_aux, dst_h3);

            int<32> dst_c3;
            if (dst_cs3_ow_aux != current_ow[7:0]) {
                dst_c3 = 0;
                dst_cs3_ow.write(dst_h3, current_ow[7:0]);
            } else {
                dst_cs3.read(dst_c3, dst_h3);
            }
            dst_c3 = dst_c3 + dst_g3;
            dst_cs3.write(dst_h3, dst_c3);

            dst_c3 = dst_g3*dst_c3;

            // Row 4 Estimate

            bit<8> dst_cs4_ow_aux;
            dst_cs4_ow.read(dst_cs4_ow_aux, dst_h4);

            int<32> dst_c4;
            if (dst_cs4_ow_aux != current_ow[7:0]) {
                dst_c4 = 0;
                dst_cs4_ow.write(dst_h4, current_ow[7:0]);
            } else {
                dst_cs4.read(dst_c4, dst_h4);
            }
            dst_c4 = dst_c4 + dst_g4;
            dst_cs4.write(dst_h4, dst_c4);

            dst_c4 = dst_g4*dst_c4;

            // Count Sketch Destination IP Frequency Estimate
            median(dst_c1, dst_c2, dst_c3, dst_c4, meta.ip_count);

            // LPM Table Lookup
            if (meta.ip_count > 0)
                dst_entropy_term.apply();
            else
                meta.entropy_term = 0;

            // Destination Entropy Norm Update
            bit<32> dst_S_aux;
            dst_S.read(dst_S_aux, 0);
            dst_S_aux = dst_S_aux + meta.entropy_term;
            dst_S.write(0, dst_S_aux);


            // Observation Window Size
            bit<32> m;
            bit<5> log2_m_aux;
            log2_m.read(log2_m_aux, 0);
            m = 32w1 << log2_m_aux;

            // Packet Count
            packet_counter.read(meta.packet_num, 0);
            meta.packet_num = meta.packet_num + 1;

            if (meta.packet_num != m) {
                packet_counter.write(0, meta.packet_num);
            } else {    // End of Observation Window
                current_ow = current_ow + 1;
                ow_counter.write(0, current_ow);

                meta.src_entropy = ((bit<32>)log2_m_aux << 4) - (src_S_aux >> log2_m_aux);
                meta.dst_entropy = ((bit<32>)log2_m_aux << 4) - (dst_S_aux >> log2_m_aux);

                src_ewma.read(meta.src_ewma, 0);
                src_ewmmd.read(meta.src_ewmmd, 0);
                dst_ewma.read(meta.dst_ewma, 0);
                dst_ewmmd.read(meta.dst_ewmmd, 0);

                if (current_ow == 1) {
                    meta.src_ewma = meta.src_entropy << 14;
                    meta.src_ewmmd = 0;
                    meta.dst_ewma = meta.dst_entropy << 14;
                    meta.dst_ewmmd = 0;
                } else {
                    meta.alarm = 0;

                    bit<32> training_len_aux;
                    training_len.read(training_len_aux, 0);
                    if (current_ow > training_len_aux) {
                        bit<8> k_aux;
                        k.read(k_aux, 0);

                        bit<32> src_thresh;
                        src_thresh = meta.src_ewma + ((bit<32>)k_aux*meta.src_ewmmd >> 3);

                        bit<32> dst_thresh;
                        dst_thresh = meta.dst_ewma - ((bit<32>)k_aux*meta.dst_ewmmd >> 3);

                        if ((meta.src_entropy << 14) > src_thresh || (meta.dst_entropy << 14) < dst_thresh)
                            meta.alarm = 1;
                    }

                    if (meta.alarm == 0) {
                        bit<8> alpha_aux;
                        alpha.read(alpha_aux, 0);

                        meta.src_ewma = (((bit<32>)alpha_aux*meta.src_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewma) >> 8);
                        if ((meta.src_entropy << 14) >= meta.src_ewma)
                           meta.src_ewmmd = (((bit<32>)alpha_aux*((meta.src_entropy << 14) - meta.src_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewmmd) >> 8);
                        else
                            meta.src_ewmmd = (((bit<32>)alpha_aux*(meta.src_ewma - (meta.src_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewmmd) >> 8);

                        meta.dst_ewma = (((bit<32>)alpha_aux*meta.dst_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewma) >> 8);
                        if ((meta.dst_entropy << 14) >= meta.dst_ewma)
                           meta.dst_ewmmd = (((bit<32>)alpha_aux*((meta.dst_entropy << 14) - meta.dst_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewmmd) >> 8);
                        else
                            meta.dst_ewmmd = (((bit<32>)alpha_aux*(meta.dst_ewma - (meta.dst_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewmmd) >> 8);
                    }
                }

                src_ewma.write(0, meta.src_ewma);
                src_ewmmd.write(0, meta.src_ewmmd);
                dst_ewma.write(0, meta.dst_ewma);
                dst_ewmmd.write(0, meta.dst_ewmmd);

                clone3(CloneType.I2E, CPU_SESSION, { meta.packet_num, meta.src_entropy, meta.src_ewma, meta.src_ewmmd, meta.dst_entropy, meta.dst_ewma, meta.dst_ewmmd, meta.alarm });

                // Reset
                packet_counter.write(0, 0);
                src_S.write(0, 0);
                dst_S.write(0, 0);
            }

            ipv4_fib.apply();
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    const bit<32> CLONE = 1;

    apply {
        if (standard_metadata.instance_type == CLONE) {
            hdr.ddosd.setValid();
            hdr.ddosd.packet_num = meta.packet_num;
            hdr.ddosd.src_entropy = meta.src_entropy;
            hdr.ddosd.src_ewma = meta.src_ewma;
            hdr.ddosd.src_ewmmd = meta.src_ewmmd;
            hdr.ddosd.dst_entropy = meta.dst_entropy;
            hdr.ddosd.dst_ewma = meta.dst_ewma;
            hdr.ddosd.dst_ewmmd = meta.dst_ewmmd;
            hdr.ddosd.alarm = meta.alarm;
            hdr.ddosd.ether_type = hdr.ethernet.ether_type;
            hdr.ethernet.ether_type = ETHERTYPE_DDOSD;
        }
    }
}

control computeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(true, {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, hdr.ipv4.hdr_checksum, HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
