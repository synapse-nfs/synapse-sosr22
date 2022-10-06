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

const port_t RECIRCULATING_PORT = 68;

const port_t CPU_PORT = 64;
const port_t LAN      = 0;
const port_t WAN      = 1;

const bit<32> PUB_ADDR      = 201459204;
const bit<32> REGISTER_SIZE = 65535; // max 16-bits

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

header reset_h {
    bit<8> value;
}

header cpu_h {
    bit<16> pub_port;
}

struct pair {
    bit<32> first;
    bit<32> second;
}

struct pair16 {
    bit<16> first;
    bit<16> second;
}

struct digest_t {
    ipv4_addr_t src_addr;
    bit<16> src_port;
    ipv4_addr_t dst_addr;
    bit<16> dst_port;
    bit<16> pub_port;
}

struct my_ingress_headers_t {
    reset_h reset;
    cpu_h cpu;
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcpudp_h tcpudp;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bool ipv4_checksum_err;
    ipv4_addr_t src_addr;
    ipv4_addr_t priv_addr;
    bit<16> port_index;
    bit<16> head;
    bit<16> src_port;
    bit<16> pub_port;
    bit<16> pub_port1;
    bit<16> priv_port;
    bit<16> norm_index;
    bit<16> rev_index;
    bit<32> ports;
    bit<32> type;
    bit<32> digest1;
    bit<32> digest2;
    bool controller;
    bool reset_register;
    bool ite_ctrl;
    bool ite_addrs;
    bool ite_ports;
    bool eti_ctrl;
    bool eti_src;
    bool eti_dst;
    bool eti_ports;
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
        tofino_parser.apply(pkt, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
            // recirculated packet
            RECIRCULATING_PORT: parse_cpu; 
            default: parse_ethernet;
        }
    }

    state parse_cpu {
        pkt.extract(hdr.reset);
        pkt.extract(hdr.cpu);
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
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash1;

    action normal_index(){
		meta.norm_index = hash.get({hdr.ipv4.src_addr,hdr.tcpudp.src_port,hdr.ipv4.dst_addr,hdr.tcpudp.dst_port});
        // meta.norm_index = hash.get({hdr.ipv4.dst_addr,hdr.tcpudp.dst_port});
	}
    
    action reversed_index(){
		meta.rev_index = hash1.get({hdr.ipv4.dst_addr,hdr.tcpudp.dst_port,PUB_ADDR,meta.pub_port});
        // meta.rev_index = hash1.get({hdr.ipv4.dst_addr,hdr.tcpudp.dst_port});
	} 

    action wan_index(){
        meta.rev_index = hash1.get({hdr.ipv4.src_addr,hdr.tcpudp.src_port});
	}

    Register<bit<16>,_>(REGISTER_SIZE) port_vector;
    Register<bit<16>,_>(1) tail;
    Register<bit<16>,_>(1) head;

    RegisterAction<bit<16>,_, bit<16>>(head) get_head = {
		void apply(inout bit<16> value, out bit<16> out_value){
            out_value = value;
        }
	};

    action get_head_action() {
        meta.head = get_head.execute(0);
    }

    RegisterAction<bit<16>,_, bit<16>>(tail) get_port_index = {
		void apply(inout bit<16> value, out bit<16> out_value){
            if ( value != meta.head ){
                value = value + 1;
            }
            out_value = value;
        }
	};

    action get_port_index_action() {
        meta.port_index = get_port_index.execute(0);
    }

    RegisterAction<bit<16>,_, bit<16>>(port_vector) get_port = {
		void apply(inout bit<16> value, out bit<16> out_value){
            out_value = value;
            value = 0;
        }
	};

    action get_port_action() {
        meta.pub_port = get_port.execute(meta.port_index);
    }

    action set_egr(port_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* int_to_ext registers */
    Register<bit<8>,_>(REGISTER_SIZE) ite_ctrl_reg;

    Register<pair,_>(REGISTER_SIZE) ite_addrs_reg;
    Register<bit<32>,_>(REGISTER_SIZE) ite_ports_reg;

    Register<bit<16>,_>(REGISTER_SIZE) ite_pub_port_reg;

    RegisterAction<bit<8>,_, bool>(ite_ctrl_reg) ite_ctrl = {
		void apply(inout bit<8> value, out bool out_value){
            if ( value == 0) {
                value = 1;
                out_value = true;
            } else {
                out_value = false;
            }
        }
	};

    action ite_ctrl_action() {
        meta.ite_ctrl = ite_ctrl.execute(meta.norm_index);
    }

    RegisterAction<bit<8>,_, void>(ite_ctrl_reg) reset_ite_ctrl = {
		void apply(inout bit<8> value){
            value = 0;
        }
	};

    action reset_ite_ctrl_action() {
        reset_ite_ctrl.execute(meta.norm_index);
    }

    RegisterAction<bit<8>,_, bool>(ite_ctrl_reg) ite_rollback_ctrl = {
		void apply(inout bit<8> value){
            value = 0;
        }
	};

    action ite_rollback_ctrl_action() {
        ite_rollback_ctrl.execute(meta.norm_index);
    }

    // UPDATES

    RegisterAction<pair,_, bool>(ite_addrs_reg) update_ite_addrs = {
		void apply(inout pair value, out bool out_value){
            out_value = true;
            value.first = hdr.ipv4.src_addr;
            value.second = hdr.ipv4.dst_addr;
        }
	};

    action update_ite_addrs_action() {
        update_ite_addrs.execute(meta.norm_index);
    }

    RegisterAction<bit<32>,_, bool>(ite_ports_reg) update_ite_ports = {
		void apply(inout bit<32> value, out bool out_value){
            out_value = true;
            value = meta.ports;
        }
	};

    action update_ite_ports_action() {
        update_ite_ports.execute(meta.norm_index);
    }

    RegisterAction<bit<16>,_, bool>(ite_pub_port_reg) update_ite_pub_port = {
		void apply(inout bit<16> value, out bool out_value){
            out_value = true;
            value = meta.pub_port;
        }
	};

    action update_ite_pub_port_action() {
        update_ite_pub_port.execute(meta.norm_index);
    }

    // CHECKS

    RegisterAction<pair,_, bool>(ite_addrs_reg) check_ite_addrs = {
		void apply(inout pair value, out bool out_value){
            if (value.first == hdr.ipv4.src_addr) {
                if (value.second == hdr.ipv4.dst_addr) {
                    out_value = true;
                } else {
                    out_value = false;
                }
            } else {
                out_value = false;
            }
        }
	};

    action check_ite_addrs_action() {
        meta.ite_addrs = check_ite_addrs.execute(meta.norm_index);
    }

    RegisterAction<bit<32>,_, bool>(ite_ports_reg) check_ite_ports = {
		void apply(inout bit<32> value, out bool out_value){
            if (value == meta.ports) {
                out_value = true;
            } else {
                out_value = false;
            }
        }
	};

    action check_ite_ports_action() {
        meta.ite_ports = check_ite_ports.execute(meta.norm_index);
    }

    // GETS

    RegisterAction<bit<16>,_, bit<16>>(ite_pub_port_reg) get_ite_pub_port = {
		void apply(inout bit<16> value, out bit<16> out_value){
            out_value = value;
        }
	};

    action get_ite_pub_port_action() {
        meta.pub_port = get_ite_pub_port.execute(meta.norm_index);
    }

    /* ext_to_int registers */

    Register<bit<8>,_>(REGISTER_SIZE) eti_ctrl_reg;
    
    Register<bit<32>,_>(REGISTER_SIZE) eti_src_reg; // Keys
    Register<bit<32>,_>(REGISTER_SIZE) eti_ports_reg;

    Register<bit<16>,_>(REGISTER_SIZE) eti_priv_port_reg;    // values
    Register<bit<32>,_>(REGISTER_SIZE) eti_priv_addr_reg;

    RegisterAction<bit<8>,_, bool>(eti_ctrl_reg) eti_ctrl = {
		void apply(inout bit<8> value, out bool out_value){
            if (value == 0){
                value = 1;
                out_value = true;
            } else {
                out_value = false;
            } 
        }
	};

    action eti_ctrl_action() {
        meta.eti_ctrl = eti_ctrl.execute(meta.rev_index);
    }

    RegisterAction<bit<8>,_, void>(eti_ctrl_reg) reset_eti_ctrl = {
		void apply(inout bit<8> value){
            value = 0;
        }
	};

    action reset_eti_ctrl_action() {
        reset_eti_ctrl.execute(meta.rev_index);
    }

    // UPDATES

    RegisterAction<bit<32>,_, bool>(eti_src_reg) update_eti_src = {
		void apply(inout bit<32> value, out bool out_value){
            out_value = true;
            value = hdr.ipv4.dst_addr;
        }
	};

    action update_eti_src_action() {
        update_eti_src.execute(meta.rev_index);
    }

    RegisterAction<bit<32>,_, bool>(eti_ports_reg) update_eti_ports = {
		void apply(inout bit<32> value, out bool out_value){
            out_value = true;
            value = meta.ports;
        }
	};

    action update_eti_ports_action() {
        update_eti_ports.execute(meta.rev_index);
    }

    RegisterAction<bit<32>,_, bool>(eti_priv_addr_reg) update_eti_priv_addr = {
		void apply(inout bit<32> value, out bool out_value){
            out_value = true;
            value = hdr.ipv4.src_addr;
        }
	};

    action update_eti_priv_addr_action() {
        update_eti_priv_addr.execute(meta.rev_index);
    }

    RegisterAction<bit<16>,_, bool>(eti_priv_port_reg) update_eti_priv_port = {
		void apply(inout bit<16> value, out bool out_value){
            out_value = true;
            value = hdr.tcpudp.src_port;
        }
	};

    action update_eti_priv_port_action() {
        update_eti_priv_port.execute(meta.rev_index);
    }
    
    // CHECKS

    RegisterAction<bit<32>,_, bool>(eti_src_reg) check_eti_src = {
		void apply(inout bit<32> value, out bool out_value){
            if (value == hdr.ipv4.src_addr) {
                out_value = true;
            } else {
                out_value = false;
            }
        }
	};

    action check_eti_src_action() {
        meta.eti_src = check_eti_src.execute(meta.norm_index);
    }

    RegisterAction<bit<32>,_, bool>(eti_ports_reg) check_eti_ports = {
		void apply(inout bit<32> value, out bool out_value){
            if (value == meta.ports) {
                out_value = true;
            } else {
                out_value = false;
            }
        }
	};

    action check_eti_ports_action() {
        meta.eti_ports = check_eti_ports.execute(meta.norm_index);
    }


    // GETS

    RegisterAction<bit<32>,_, bit<32>>(eti_priv_addr_reg) get_eti_priv_addr = {
		void apply(inout bit<32> value, out bit<32> out_value){
            out_value = value;
        }
	};

    action get_eti_priv_addr_action() {
        meta.priv_addr = get_eti_priv_addr.execute(meta.norm_index);
    }

    RegisterAction<bit<16>,_, bit<16>>(eti_priv_port_reg) get_eti_priv_port = {
		void apply(inout bit<16> value, out bit<16> out_value){
            out_value = value;
        }
	};

    action get_eti_priv_port_action() {
        meta.priv_port = get_eti_priv_port.execute(meta.norm_index);
    }





    action ite_process(/*bit<32> address,*/ bit<16> port){
        // hdr.ipv4.src_addr = address;
        meta.pub_port = port; // returns public port
    }

    action return_0(){
        meta.pub_port = 0;
    }

    action eti_process(bit<32> address, bit<16> port){
        hdr.ipv4.dst_addr = address; // switch's public address is replaced with the private address according to the corresponding public port
        hdr.tcpudp.dst_port = port;    // switch's public port is replaced with the private port according to the corresponding public port
        set_egr(LAN);
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
            return_0;
        }

        size = 65536;
        const default_action = return_0;
        idle_timeout = true;
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

        size = 65536;
        const default_action = drop();
    }

    apply {

        if(!hdr.cpu.isValid()) {
            meta.ports = hdr.tcpudp.src_port ++ hdr.tcpudp.dst_port;

            meta.controller = false;
            meta.reset_register = false;

            // check if it is different than WAN in order to receive packets from
            // the controller as LAN packets
            if (ig_intr_md.ingress_port != WAN) {

                nat_int_to_ext.apply();     // does it exist in a table?
                normal_index();
                if ( meta.pub_port == 0) {
                    ite_ctrl_action();   // verify control (int-to-ext) is something inside?
                    if ( meta.ite_ctrl ) {      // no?
                        get_head_action();
                        get_port_index_action();
                        get_port_action();          // generate new port
                        if ( meta.pub_port != 0 ) { // no?
                            reversed_index();                // generate new hash
                            eti_ctrl_action();   // verify control (ext-to-int) is something inside?
                            if ( meta.eti_ctrl ) {      // register empty?
                                update_ite_addrs_action();           // update both
                                update_ite_ports_action();

                                meta.ports = hdr.tcpudp.dst_port ++ meta.pub_port;

                                update_ite_pub_port_action();
                                update_eti_src_action();
                                update_eti_ports_action();
                                update_eti_priv_addr_action();
                                update_eti_priv_port_action();
                                ig_dprsr_md.digest_type = 1;    // set to send digest to controller
                            } else {                    // not empty?
                                meta.controller = true;    // controller after recirculation
                                hdr.cpu.setValid();
                                set_egr(RECIRCULATING_PORT);
                            }
                        } else {
                            meta.controller = true;
                            hdr.cpu.setValid();
                            set_egr(RECIRCULATING_PORT);
                        }
                    } else {
                        check_ite_addrs_action();
                        check_ite_ports_action();
                        if ( meta.ite_addrs && meta.ite_ports) { //same?
                            get_ite_pub_port_action();
                        } else {
                            meta.controller = true;     // send_to_controller
                            meta.pub_port = 0;
                            hdr.cpu.setValid();
                            set_egr(CPU_PORT);
                        }
                    }
                } else {    // clean register
                    ite_ctrl_action();   // verify control (int-to-ext) is something inside?
                    check_ite_addrs_action();
                    check_ite_ports_action();

                    if ( meta.ite_ctrl && meta.ite_addrs && meta.ite_ports) { //same?
                        meta.controller = true;    // controller after recirculation
                        meta.reset_register = true;

                        hdr.cpu.setValid();
                        set_egr(RECIRCULATING_PORT);
                    }    
                }

                if (!meta.controller) {
                    hdr.ipv4.src_addr = PUB_ADDR;
                    hdr.tcpudp.src_port = meta.pub_port;
                    set_egr(WAN);
                }
            } else {    //  WAN processing
                wan_index();
                
                check_eti_src_action();
                check_eti_ports_action();
                if ( meta.eti_src && meta.eti_ports) {
                    get_eti_priv_addr_action();
                    get_eti_priv_port_action();
                    hdr.ipv4.dst_addr = meta.priv_addr;
                    hdr.tcpudp.dst_port = meta.priv_port;
                    set_egr(LAN);
                } else {
                    nat_ext_to_int.apply();
                }
            }
        } else {    // inside recirculated packet
            // hdr.ethernet.src_addr = 16w0 ++ PUB_ADDR;
            // hdr.ethernet.dst_addr = 32w0 ++ hdr.recirculate.pub_port;

            if ( hdr.reset.value == 1 ) {   // clean register
                hdr.reset.setInvalid();
                hdr.cpu.setInvalid();

                normal_index();
                meta.pub_port = hdr.cpu.pub_port;
                reversed_index();

                reset_ite_ctrl_action();
                reset_eti_ctrl_action();
                set_egr(WAN);  // not sent to controller
            } else {                        // rollback counter
                hdr.reset.setInvalid();
                ite_rollback_ctrl_action();
                set_egr(CPU_PORT);
            }
        }

        if (meta.controller){
            hdr.reset.setValid();
            if ( meta.reset_register ) {
                hdr.reset.value = 1;
            } else {
                hdr.reset.value = 0;
            }
            hdr.cpu.pub_port = meta.pub_port;
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
    Digest<digest_t>() digest;

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

        if (ig_dprsr_md.digest_type == 1) {
            digest.pack({hdr.ipv4.src_addr,hdr.tcpudp.src_port,hdr.ipv4.dst_addr,hdr.tcpudp.dst_port,meta.pub_port});
        }
        
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
