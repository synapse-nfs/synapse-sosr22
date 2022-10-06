/* -* P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

typedef bit<9> port_t;

const port_t CPU_PORT = 64;
const port_t LAN      = 0;
const port_t WAN      = 1;

const bit<32> PUB_ADDR      = 201459204;
const bit<32> REGISTER_SIZE = 65535; // max 16-bits

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

struct my_ingress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcpudp_h tcpudp;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bool ipv4_checksum_err;
}

/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md) {
    
    TofinoIngressParser() tofino_parser;
    Checksum() ipv4_checksum;
    
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        meta.ipv4_checksum_err = false;

        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        ipv4_checksum.add(hdr.ipv4);
        meta.ipv4_checksum_err = ipv4_checksum.verify();

        transition select (hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcpudp;
            IP_PROTOCOLS_UDP: parse_tcpudp;
            default: accept;
        }
    }

    state parse_tcpudp {
        pkt.extract(hdr.tcpudp);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action fwd(port_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action send_to_cpu(){
        fwd(CPU_PORT);
    }

    action ite_process(bit<16> port){
        // private IP address is replaced with the switch's
        // public IP address
        hdr.ipv4.src_addr = PUB_ADDR;

        // private port is replaced by a generated public port
        // via monotonically increasing counter
        hdr.tcpudp.src_port = port;

        fwd(WAN);
    }

    action eti_process(bit<32> address, bit<16> port){
        // switch's public address is replaced with the private address
        // according to the corresponding public port
        hdr.ipv4.dst_addr = address;

        // switch's public port is replaced with the private port
        // according to the corresponding public port
        hdr.tcpudp.dst_port = port;

        fwd(LAN);
    }

    table nat_int_to_ext {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.tcpudp.src_port: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.tcpudp.dst_port: exact;
        }

        actions = {
            ite_process;
            send_to_cpu;
        }

        const default_action = send_to_cpu();
        idle_timeout = true;
        size = 65536;
    }

    table nat_ext_to_int {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.tcpudp.src_port: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.tcpudp.dst_port: exact;
        }

        actions = {
            eti_process;
            drop;
        }

        const default_action = drop();
        size = 65536;
    }

    apply {
        if (ig_intr_md.ingress_port != WAN) {
            nat_int_to_ext.apply();
        } else {
            nat_ext_to_int.apply();
        }

        ig_tm_md.bypass_egress = 1w1;
    }
}

/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });
        
        pkt.emit(hdr);
    }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;
