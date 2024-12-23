#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define FLOW_ID_UPBOUND 65535
#define LOGICAL_INDEX 16
#define SWITCH_SIZE 10
#define BIT_SIZE 11
#define PIPE_NUM 4

struct flow_t{
    bit<32>   dst_addr;
    bit<32>   src_addr;
    bit<16>   dst_port;
    bit<16>   src_port;
    bit<8>    protocol;
}


struct metadata_t { 
    bit<8> deltaValue;
    bit<32>flowID;
    bit<32> outFlowID;
    bit<8>registerValue;

    bit<8> cur_min_delta_1;//for first delta sketch
    bit<8> cur_min_delta_2;//for second delta sketch
    bit<1> add_hdr;
    bit<1> flag;
    bit<32> monitorPipe;
    bit<32> realPipe;

}

header custom_metadata_t{
    bit<32> flowID;
    bit<8> delta;
}

header ethernet_t{
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16>   ether_type;
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
    bit<32>   src_addr;
    bit<32>   dst_addr;
}


struct Pair{
    bit<32> value;
    bit<32>flag;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;

    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct header_t{
    ethernet_t ethernet;  
    ipv4_t ipv4;
    tcp_h tcp;
    udp_h udp;
    custom_metadata_t custom_metadata;
}



// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t conMeta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x800 : parse_ipv4;
            default : accept;
        }
    }


    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17 : parse_udp;
            6 : parse_tcp;
            default : reject;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t conMeta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
//         pkt.emit(hdr.custom_metadata);
    }
}

control SwitchIngress(
        inout header_t hdr,
        //inout metadata_t ig_md,
        inout metadata_t conMeta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
        ) {



    action forward(PortId_t port){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        ig_tm_md.ucast_egress_port = port;

    }
    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }
    table table_forward{
        key = {
            hdr.ipv4.dst_addr : exact;
        }

        actions = {
            forward;
            drop;
        }
        const default_action = drop;
        size = 1024;
    }

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly1;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash_func1;

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly2;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly2) hash_func2;

    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly3;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly3) hash_func3;

     CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly4;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly4) hash_func4;

     CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly5;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly5) hash_func5;

    //count-min sketch, each has 2 row
    Register<bit<8>, bit<10>>(size=1024, initial_value=0) deltaSketch1_1;
    RegisterAction<bit<8>, bit<10>, bit<8>>(deltaSketch1_1) getDeltaSketch1_1= {
        void apply(inout bit<8> value, out bit<8> read_value){
            read_value = value;
            if(conMeta.cur_min_delta_1 > value){
                value = 0;
            }
            else {
                value = value - conMeta.cur_min_delta_1;
            }
        }
    };

    RegisterAction<bit<8>, bit<10>, void>(deltaSketch1_1) setDeltaSketch1_1 = {
        void apply(inout bit<8> value){
            value = value + 1;
        }
    };

    Register<bit<8>, bit<10>>(size=1024, initial_value=0) deltaSketch1_2;
    RegisterAction<bit<8>, bit<10>, bit<8>>(deltaSketch1_2) getDeltaSketch1_2= {
        void apply(inout bit<8> value, out bit<8> read_value){
            read_value = value;
            if(conMeta.cur_min_delta_1 > value){
                value = 0;
            }
            else {
                value = value - conMeta.cur_min_delta_1;
            }
        }
    };

    RegisterAction<bit<8>, bit<10>, void>(deltaSketch1_2) setDeltaSketch1_2 = {
        void apply(inout bit<8> value){
            value = value + 1;
        }
    };

    Register<bit<8>, bit<10>>(size=1024, initial_value=0) deltaSketch2_1;
    RegisterAction<bit<8>, bit<10>, bit<8>>(deltaSketch2_1) getDeltaSketch2_1= {
        void apply(inout bit<8> value, out bit<8> read_value){
            read_value = value;
            if(conMeta.cur_min_delta_2 > value){
                value = 0;
            }
            else {
                value = value - conMeta.cur_min_delta_2;
            }
        }
    };

    RegisterAction<bit<8>, bit<10>, void>(deltaSketch2_1) setDeltaSketch2_1 = {
        void apply(inout bit<8> value){
            value = value + 1;
        }
    };

    Register<bit<8>, bit<10>>(size=1024, initial_value=0) deltaSketch2_2;
    RegisterAction<bit<8>, bit<10>, bit<8>>(deltaSketch2_2) getDeltaSketch2_2= {
        void apply(inout bit<8> value, out bit<8> read_value){
            read_value = value;
            if(conMeta.cur_min_delta_2 > value){
                value = 0;
            }
            else {
                value = value - conMeta.cur_min_delta_2;
            }
        }
    };

    RegisterAction<bit<8>, bit<10>, void>(deltaSketch2_2) setDeltaSketch2_2 = {
        void apply(inout bit<8> value){
            value = value + 1;
        }
    };

    //c = 1
    Register<Pair, bit<32>>(size=32w4) pipeTable1_1;
    RegisterAction<Pair, bit<32>, void>(pipeTable1_1) setTable1_1= {
        void apply(inout Pair value){
            value.value = conMeta.flowID;
            value.flag = 1;
        }
    };
    RegisterAction<Pair, bit<32>, bit<32>>(pipeTable1_1) getTable1_1 = {
        void apply(inout Pair value, out bit<32> read_value){
            if(value.flag==1){
                read_value = value.value;
                value.flag = 0;
            }else{
                read_value = 0; 
            }
        }
    };

    Register<Pair, bit<32>>(size=32w4) pipeTable1_2;
    RegisterAction<Pair, bit<32>, void>(pipeTable1_2) setTable1_2= {
        void apply(inout Pair value){
            value.value = conMeta.flowID;
            value.flag = 1;
        }
    };
    RegisterAction<Pair, bit<32>, bit<32>>(pipeTable1_2) getTable1_2 = {
        void apply(inout Pair value, out bit<32> read_value){
            if(value.flag==1){
                read_value = value.value;
                value.flag = 0;
            }else{
                read_value = 0; 
            }
        }
    };

    //c = 2 
    Register<Pair, bit<32>>(size=32w4) pipeTable2_1;
    RegisterAction<Pair, bit<32>, void>(pipeTable2_1) setTable2_1= {
        void apply(inout Pair value){
            value.value = conMeta.flowID;
            value.flag = 1;
        }
    };
    RegisterAction<Pair, bit<32>, bit<32>>(pipeTable2_1) getTable2_1 = {
        void apply(inout Pair value, out bit<32> read_value){
            if(value.flag==1){
                read_value = value.value;
                value.flag = 0;
            }else{
                read_value = 0; 
            }
        }
    };

    Register<Pair, bit<32>>(size=32w4) pipeTable2_2;
    RegisterAction<Pair, bit<32>, void>(pipeTable2_2) setTable2_2= {
        void apply(inout Pair value){
            value.value = conMeta.flowID;
            value.flag = 1;
        }
    };
    RegisterAction<Pair, bit<32>, bit<32>>(pipeTable2_2) getTable2_2 = {
        void apply(inout Pair value, out bit<32> read_value){
            if(value.flag==1){
                read_value = value.value;
                value.flag = 0;
            }else{
                read_value = 0; 
            }
        }
    };

    
    Register<bit<32>, bit<1>>(1) pkt_cnt_reg;
    RegisterAction<bit<32>, bit<1>, bit<1>>(pkt_cnt_reg) update_pkt_cnt_reg = {
        void apply(inout bit<32> value, out bit<1> flag){
            value = value + 1;
            flag = (bit<1>)value;
        }
    };
    
    //four pipe's pipetable pointer, c = 2
    Register<bit<32>, bit<1>>(1) c_pointer_reg_1;
    RegisterAction<bit<32>, bit<1>, bit<32>>(c_pointer_reg_1) update_c_pointer_reg_1 = {
        void apply(inout bit<32> value, out bit<32> ans){
            if(value == 1){
                value = 0;
                ans = 1;
            }
            else{
                value = 1;
                ans = 0;
            }
        }
    };
    Register<bit<32>, bit<1>>(1) c_pointer_reg_2;
    RegisterAction<bit<32>, bit<1>, bit<32>>(c_pointer_reg_2) update_c_pointer_reg_2 = {
        void apply(inout bit<32> value, out bit<32> ans){
            if(value == 1){
                value = 0;
                ans = 1;
            }
            else{
                value = 1;
                ans = 0;
            }
        }
    };
    Register<bit<32>, bit<1>>(1) c_pointer_reg_3;
    RegisterAction<bit<32>, bit<1>, bit<32>>(c_pointer_reg_3) update_c_pointer_reg_3 = {
        void apply(inout bit<32> value, out bit<32> ans){
            if(value == 1){
                value = 0;
                ans = 1;
            }
            else{
                value = 1;
                ans = 0;
            }
        }
    };
    Register<bit<32>, bit<1>>(1) c_pointer_reg_4;
    RegisterAction<bit<32>, bit<1>, bit<32>>(c_pointer_reg_4) update_c_pointer_reg_4 = {
        void apply(inout bit<32> value, out bit<32> ans){
            if(value == 1){
                value = 0;
                ans = 1;
            }
            else{
                value = 1;
                ans = 0;
            }
        }
    };
    
    
    Register<bit<32>, bit<1>>(1) test_cnt;
    RegisterAction<bit<32>, bit<1>, bit<1>>(test_cnt) update_test_cnt = {
        void apply(inout bit<32> value, out bit<1> ans){
            value = (bit<32>)conMeta.flag;
        }
    };
    
    Register<bit<8>, bit<1>>(1) test_delta;
    RegisterAction<bit<8>, bit<1>, bit<8>>(test_delta) update_test_delta = {
        void apply(inout bit<8> value, out bit<8> ans){
            value = conMeta.cur_min_delta_1;
        }
    };
    
    Register<bit<32>, bit<1>>(1) test_monitor;
    RegisterAction<bit<32>, bit<1>, bit<32>>(test_monitor) update_test_monitor = {
        void apply(inout bit<32> value, out bit<32> ans){
            value = conMeta.monitorPipe;
        }
    };
        
    Register<bit<32>, bit<1>>(1) test_real;
    RegisterAction<bit<32>, bit<1>, bit<32>>(test_real) update_test_real = {
        void apply(inout bit<32> value, out bit<32> ans){
            value = conMeta.realPipe;
        }
    };



    apply{
        //1 -> odd, 0 -> even
        bit<1> odd_or_even = update_pkt_cnt_reg.execute(0);
        conMeta.flag = odd_or_even;
        //update_test_cnt.execute(0);
        //出口pipe
        bit<2> real_pipe_ = (bit<2>)ig_tm_md.ucast_egress_port;
        bit<32> real_pipe = (bit<32>)real_pipe_;

        //conMeta.flowID is hashed 32bit id, for calculate monitor pipe
        conMeta.flowID = hash_func1.get({hdr.ipv4.dst_addr,
                                        hdr.ipv4.src_addr,
                                        hdr.tcp.dst_port,
                                        hdr.tcp.src_port,
                                        hdr.ipv4.protocol});   
        //4 pipe
        bit<2> monitor_pipe_ = (bit<2>)conMeta.flowID;
        bit<32> monitor_pipe = (bit<32>)monitor_pipe_;
        conMeta.monitorPipe = monitor_pipe;
        //update_test_monitor.execute(0);
        

        bit<32> flow_id;
        bit<32> delta_value;
        bit<8> before_value;
        bit<8> min_delta_1;
        bit<8> min_delta_2;

        //find pipetable's tail
        bit<32> c_pointer_set_;
        bit<32> c_pointer_get_;
        if (monitor_pipe_ != real_pipe_){
            if(monitor_pipe_ == 0){
                c_pointer_set_ = update_c_pointer_reg_1.execute(0);
            }
            else if(monitor_pipe_ == 1){
                c_pointer_set_ = update_c_pointer_reg_2.execute(0);
            }
            else if(monitor_pipe_ == 2){
                c_pointer_set_ = update_c_pointer_reg_3.execute(0);
            }
            else{
                c_pointer_set_ = update_c_pointer_reg_4.execute(0);
            }
            if(real_pipe == 0){
                c_pointer_get_ = update_c_pointer_reg_1.execute(0);
            }
            else if(real_pipe_ == 1){
                c_pointer_get_ = update_c_pointer_reg_2.execute(0);
            }
            else if(real_pipe_ == 2){
                c_pointer_get_ = update_c_pointer_reg_3.execute(0);
            }
            else{
                c_pointer_get_ = update_c_pointer_reg_4.execute(0);
            }
        }
        else {
            if(monitor_pipe_ == 0){
                c_pointer_set_ = update_c_pointer_reg_1.execute(0);
            }
            else if(monitor_pipe_ == 1){
                c_pointer_set_ = update_c_pointer_reg_2.execute(0);
            }
            else if(monitor_pipe_ == 2){
                c_pointer_set_ = update_c_pointer_reg_3.execute(0);
            }
            else{
                c_pointer_set_ = update_c_pointer_reg_4.execute(0);
            }
            c_pointer_get_ = c_pointer_set_;
        }
        bit<1> c_pointer_set = (bit<1>)c_pointer_set_;
        bit<1> c_pointer_get = (bit<1>)c_pointer_get_;
        bit<10> delta_index_set1 = (bit<10>)hash_func4.get({hdr.ipv4.dst_addr,
                                                            hdr.ipv4.src_addr,
                                                            hdr.tcp.dst_port,
                                                            hdr.tcp.src_port,
                                                            hdr.ipv4.protocol});
        bit<10> delta_index_set2 = (bit<10>)hash_func5.get({hdr.ipv4.dst_addr,
                                                            hdr.ipv4.src_addr,
                                                            hdr.tcp.dst_port,
                                                            hdr.tcp.src_port,
                                                            hdr.ipv4.protocol});
        
            if(odd_or_even == 0){
                conMeta.cur_min_delta_1 = 0;
                //execute pipetable
                if(c_pointer_set == 0){
                    setTable2_1.execute(monitor_pipe);
                }
                else{
                    setTable2_2.execute(monitor_pipe);
                }
                if(c_pointer_get == 0){
                    flow_id = getTable1_2.execute(real_pipe);
                }
                else{
                    flow_id = getTable1_1.execute(real_pipe);
                }
                

                setDeltaSketch2_1.execute(delta_index_set1);
                setDeltaSketch2_2.execute(delta_index_set2);
                if(flow_id != 0){
                    //real pipe data out 
                    //delta sketch w = 1024
                    //avoid collision in same stage
                    bit<1> stage_pass = 0;
                    if(stage_pass == 0){
                        
                        bit<10> delta_index_get1 = (bit<10>)hash_func2.get({flow_id});
                        bit<10> delta_index_get2 = (bit<10>)hash_func3.get({flow_id});
                        min_delta_1 = getDeltaSketch1_1.execute(delta_index_get1);
                        before_value = getDeltaSketch1_2.execute(delta_index_get2);
                    }
                    stage_pass = stage_pass + 1;
                    if(stage_pass == 1){
                        //monitor pipe data in
                        
                        
        //                 conMeta.outFlowID = flow_id;
                        conMeta.add_hdr = 1;
                    }
                    
                    hdr.custom_metadata.setValid();
                    hdr.custom_metadata.flowID = flow_id;
                    hdr.custom_metadata.delta = min_delta_1;
                }
            }
            else{
                conMeta.cur_min_delta_2 = 0;
                if(c_pointer_set == 0){
                    setTable1_1.execute(monitor_pipe);
                }
                else{
                    setTable1_2.execute(monitor_pipe);
                }
                if(c_pointer_get == 0){
                    flow_id = getTable2_2.execute(real_pipe);
                }
                else{
                    flow_id = getTable2_1.execute(real_pipe);
                }
                setDeltaSketch1_1.execute(delta_index_set1);
                setDeltaSketch1_2.execute(delta_index_set2);
        //                 conMeta.outFlowID = flow_id;
                if(flow_id != 0){
                    bit <1> stage_pass = 0;
                    
                    if(stage_pass == 0){
                        bit<10> delta_index_get1 = (bit<10>)hash_func2.get({flow_id});
                        bit<10> delta_index_get2 = (bit<10>)hash_func3.get({flow_id});

                        min_delta_2 = getDeltaSketch2_1.execute(delta_index_get1);
                        before_value = getDeltaSketch2_2.execute(delta_index_get2);
                        
                    }
                    stage_pass = stage_pass + 1;
                    if (stage_pass == 1){
                        stage_pass = stage_pass - 1;
                    }
                    
                    if (stage_pass == 0){
                        
                        conMeta.add_hdr = 1;
                    }
                    
                    hdr.custom_metadata.delta = min_delta_2;
                }
            }
            if (conMeta.add_hdr == 1){
                hdr.custom_metadata.setValid();
                hdr.custom_metadata.flowID = flow_id;
                if(odd_or_even == 0){
                    if(min_delta_1 > before_value){
                        min_delta_1 = before_value;
                    }
                }
                else{
                    if(min_delta_2 > before_value){
                        min_delta_2 = before_value;
                    }
                }
            }
            //update_test_delta.execute(0);
            table_forward.apply();
        
        
        


        
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t distribute_meta,
        out egress_intrinsic_metadata_t eg_intr_md) {

TofinoEgressParser() tofino_eparser;
    state start {
        tofino_eparser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x800 : parse_ipv4;
            default : accept;
        }
        
    }


    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17 : parse_tcp;
            6 : parse_udp;
            default : reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

}

control SwitchEgressDeparser(        
        packet_out pkt,
        inout header_t hdr,
        in metadata_t distribute_meta,
        in egress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        //pkt.emit(hdr.custom_metadata);
    }
}


control SwitchEgress(
        inout header_t hdr,
        //inout metadata_t ig_md,
        inout metadata_t distribute_meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport
        ) {

    apply {
        // hdr.udp.data = hdr.custom_metadata.data;
        // hdr.custom_metadata.setValid();
        // hdr.udp.result = hdr.custom_metadata.data10;
    }

}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------


Pipeline(SwitchIngressParser(),
       SwitchIngress(),
       SwitchIngressDeparser(),
        SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
