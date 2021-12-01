/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_CLONE_SESSION_ID 100
#define CPU_PORT 3
#define CLONED 1

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_EXTRA = 0xA1;

const bit<32> CNT_INDEX = 32w0;
const bit<32> TCP_INDEX = 32w1;
const bit<32> TCP_SYN_INDEX = 32w2;
const bit<32> UDP_INDEX = 32w3;
const bit<32> ICMP_INDEX = 32w4;
const bit<32> LENGTH_INDEX = 32w5;

const bit<16> EXTRA_SIZE = 16w24;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

register<bit<32>>(32w6) pkt_cnt;

const bit<32> LAST_SEND_TIME_INDEX = 32w0;
const bit<48> TIME_TO_SEND = 48w3000000;

register<bit<48>>(32w1) timestamp;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> optData;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNum;
    bit<32> ackNum;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> windowSize;
    bit<16> hrdChecksum;
    bit<16> urgPtr;
}

header extra_t {
    bit<32> total_pck;
    bit<32> tcp_pck;
    bit<32> tcp_syn_pck;
    bit<32> udp_pck;
    bit<32> icmp_pck;
    bit<32> total_len;
}

struct metadata {
    bit<9> ingress_port;
    bit<9> egress_spec;
    bit<9> egress_port;
    bit<32> pkt_count;
    bit<32> udp_count;
    bit<32> tcp_count;
    bit<32> icmp_count;
    bit<32> tcp_syn_count;
    bit<32> length_count;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    udp_t        udp;
    tcp_t        tcp;
    extra_t      extra;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType)
        {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol)
        {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }


}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action do_copy() {
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata });
    }
    
    action timestamp_update(in bit<32> timestamp_to_update_index)
    {
        timestamp.write(timestamp_to_update_index,standard_metadata.ingress_global_timestamp);
    }

    action add_cnt(in bit<32> counter_index,inout bit<32> meta_value, in bit<32> increment_by_value) {
        pkt_cnt.read(meta_value, counter_index);
        meta_value = meta_value + increment_by_value;
        pkt_cnt.write(counter_index, meta_value);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    table copy {
        actions = {
            do_copy;
        }
        size = 1;
        default_action = do_copy();
    }

    apply {

        if(hdr.ipv4.isValid()){

            bit<48> ts = 0;
            
            timestamp.read(ts, LAST_SEND_TIME_INDEX);

            add_cnt(CNT_INDEX,meta.pkt_count,1);
            add_cnt(LENGTH_INDEX,meta.length_count,standard_metadata.packet_length);
            if(hdr.tcp.isValid()){
                add_cnt(TCP_INDEX,meta.tcp_count,1);
                if(hdr.tcp.syn == 0x01)
                {
                    add_cnt(TCP_SYN_INDEX,meta.tcp_syn_count,1);
                }
            }

            if(hdr.udp.isValid()){
                add_cnt(UDP_INDEX,meta.udp_count,1);
            }

            if(hdr.ipv4.protocol == TYPE_ICMP){
                add_cnt(ICMP_INDEX,meta.icmp_count,1);
            }

            if(standard_metadata.ingress_global_timestamp - ts > TIME_TO_SEND)
            {
                timestamp_update(LAST_SEND_TIME_INDEX);
                copy.apply();
            }
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
************************************************************************
truncate function cuts cloned and modified packet containing extra header
to hardcoded size, because in earlier stages cloned packet could have
big sizes with unecessary random data copied from original packet.
*/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    apply { 
        if(standard_metadata.instance_type == CLONED)
        {
            hdr.extra.setValid();
            pkt_cnt.read(hdr.extra.total_pck,CNT_INDEX);
            pkt_cnt.read(hdr.extra.tcp_pck,TCP_INDEX);
            pkt_cnt.read(hdr.extra.tcp_syn_pck,TCP_SYN_INDEX);
            pkt_cnt.read(hdr.extra.udp_pck,UDP_INDEX);
            pkt_cnt.read(hdr.extra.icmp_pck,ICMP_INDEX);
            pkt_cnt.read(hdr.extra.total_len,LENGTH_INDEX);
            
            if(hdr.ipv4.protocol == TYPE_TCP)
            {
                hdr.tcp.setInvalid();
            }
            if(hdr.ipv4.protocol == TYPE_UDP)
            {
                hdr.udp.setInvalid();
            }

            if(hdr.ipv4.protocol == TYPE_ICMP)
            {
                hdr.icmp.setInvalid();
            }

            truncate(32w96);
            
            hdr.ipv4.protocol = TYPE_EXTRA;
            hdr.ipv4.totalLen = 16w20 + EXTRA_SIZE;

            pkt_cnt.write(CNT_INDEX,0);
            pkt_cnt.write(TCP_INDEX,0);
            pkt_cnt.write(TCP_SYN_INDEX,0);
            pkt_cnt.write(UDP_INDEX,0);
            pkt_cnt.write(ICMP_INDEX,0);
            pkt_cnt.write(LENGTH_INDEX,0);

        }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.extra);
        
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;