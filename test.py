# PTF test for main
# p4testgen seed: 1000

import logging
import itertools

from bfruntime_client_base_tests import BfRuntimeTest
from ptf.mask import Mask
from ptf.testutils import send_packet
from ptf.testutils import verify_packet
from ptf.testutils import verify_no_other_packets
from ptf import config
import ptf.testutils as testutils

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import time

logger = logging.getLogger('confluence')
logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    if len(swports) >= 4:
        break
swports.sort()
print(swports)

class AbstractTest(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, 'confluence')
        self.dev_id = 0
        self.table_entries = []
        self.bfrt_info = None
        # Get bfrt_info and set it as part of the test.
        self.bfrt_info = self.interface.bfrt_info_get('confluence')

        # Set target to all pipes on device self.dev_id.
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)

    def tearDown(self):
        # Reset tables.
        for elt in reversed(self.table_entries):
            test_table = self.bfrt_info.table_get(elt[0])
            test_table.entry_del(self.target, elt[1])
        self.table_entries = []

        # End session.
        BfRuntimeTest.tearDown(self)

    def insertTableEntry(
        self, table_name, key_fields=None, action_name=None, data_fields=[]
    ):
        test_table = self.bfrt_info.table_get(table_name)
        key_list = [test_table.make_key(key_fields)]
        data_list = [test_table.make_data(data_fields, action_name)]
        test_table.entry_add(self.target, key_list, data_list)
        self.table_entries.append((table_name, key_list))

    def _responseDumpHelper(self, request):
        for response in self.interface.stub.Read(request, timeout=2):
            yield response

    def overrideDefaultEntry(self, table_name, action_name=None, data_fields=[]):
        test_table = self.bfrt_info.table_get(table_name)
        data = test_table.make_data(data_fields, action_name)
        test_table.default_entry_set(self.target, data)

    def setRegisterValue(self, reg_name, value, index):
        reg_table = self.bfrt_info.table_get(reg_name)
        key_list = [reg_table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])]
        value_list = []
        if isinstance(value, list):
            for val in value:
                value_list.append(gc.DataTuple(val[0], val[1]))
        else:
            value_list.append(gc.DataTuple("f1", value))
        reg_table.entry_add(self.target, key_list, [reg_table.make_data(value_list)])

    def entryAdd(self, table_obj, target, table_entry):
        req = bfruntime_pb2.WriteRequest()
        gc._cpy_target(req, target)
        req.atomicity = bfruntime_pb2.WriteRequest.CONTINUE_ON_ERROR
        update = req.updates.add()
        update.type = bfruntime_pb2.Update.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        resp = self.interface.reader_writer_interface._write(req)
        table_obj.get_parser._parse_entry_write_response(resp)

    def setDirectRegisterValue(self, tbl_name, value):
        test_table = self.bfrt_info.table_get(tbl_name)
        table_id = test_table.info.id
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        gc._cpy_target(req, self.target)
        entity = req.entities.add()
        table = entity.table_entry
        table.table_id = table_id
        table_entry = None
        for response in self._responseDumpHelper(req):
            for entity in response.entities:
                assert entity.WhichOneof("entity") == "table_entry"
                table_entry = entity.table_entry
                break
        if table_entry is None:
            raise self.failureException(
                "No entry in the table that the meter is attached to."
            )
        table_entry.ClearField("data")
        value_list = []
        if isinstance(value, list):
            for val in value:
                df = table_entry.data.fields.add()
        else:
            df = table_entry.data.fields.add()
            df.value = gc.DataTuple(gc.DataTuple("f1", value))
        self.entryAdd(test_table, self.target, table_entry)

    def setupCtrlPlane(self):
        pass

    def sendPacket(self):
        pass

    def verifyPackets(self):
        pass

    def runTestImpl(self):
        self.setupCtrlPlane()
        logger.info("Sending Packet ...")
        self.sendPacket()
        logger.info("Verifying Packet ...")
        self.verifyPackets()
        logger.info("Verifying no other packets ...")
        #verify_no_other_packets(self, self.dev_id, timeout=2)

class Test0(AbstractTest):

    def setupCtrlPlane(self):
        self.setRegisterValue('SwitchIngress.pkt_cnt_reg', 0x00000003, 0)
        self.setRegisterValue('SwitchIngress.test_monitor', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.test_cnt', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.test_delta', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.c_pointer_reg_1', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.c_pointer_reg_2', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.c_pointer_reg_3', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.c_pointer_reg_4', 0x00000000, 0)
        for i in range(4):
            self.setRegisterValue('SwitchIngress.pipeTable2_1', [('SwitchIngress.pipeTable2_1.value', 0x00000000), ('SwitchIngress.pipeTable2_1.flag', 0x00000000)], i)
            self.setRegisterValue('SwitchIngress.pipeTable2_2', [('SwitchIngress.pipeTable2_2.value', 0x00000000), ('SwitchIngress.pipeTable2_2.flag', 0x00000000)], i)
            self.setRegisterValue('SwitchIngress.pipeTable1_1', [('SwitchIngress.pipeTable1_1.value', 0x00000000), ('SwitchIngress.pipeTable1_1.flag', 0x00000000)], i)
            self.setRegisterValue('SwitchIngress.pipeTable1_2', [('SwitchIngress.pipeTable1_2.value', 0x00000000), ('SwitchIngress.pipeTable1_2.flag', 0x00000000)], i)
        for i in range(1024):
            self.setRegisterValue('SwitchIngress.deltaSketch1_1', 0x00, i)
            self.setRegisterValue('SwitchIngress.deltaSketch1_2', 0x00, i)
            self.setRegisterValue('SwitchIngress.deltaSketch2_1', 0x00, i)
            self.setRegisterValue('SwitchIngress.deltaSketch2_2', 0x00, i)
        self.insertTableEntry(
            'SwitchIngress.table_forward',
            [
                gc.KeyTuple('hdr.ipv4.dst_addr', 0xC0A80102),
            ],
            'SwitchIngress.forward',
            [
                gc.DataTuple('port', swports[1])  # 端口号作为数据字段
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_forward',
            [
                gc.KeyTuple('hdr.ipv4.dst_addr', 0xC0A80103),
            ],
            'SwitchIngress.forward',
            [
                gc.DataTuple('port', swports[1])  # 端口号作为数据字段
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_forward',
            [
                gc.KeyTuple('hdr.ipv4.dst_addr', 0xC0A80104),
            ],
            'SwitchIngress.forward',
            [
                gc.DataTuple('port', swports[1])  # 端口号作为数据字段
            ]
        )


    def sendPacket(self):
        ig_port = swports[0]

        
        packet1 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='192.168.1.2',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet2 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='192.168.1.3',
                                   ip_src='19.148.12.133',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet3 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='192.168.1.4',
                                   ip_src='92.18.152.11',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        send_packet(self, ig_port, packet1)
        time.sleep(1)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.test_monitor")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        #send_packet(self, ig_port, packet2)
        #time.sleep(1)
        #register_table = self.bfrt_info.table_get("SwitchIngress.test_monitor")
        #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        #send_packet(self, ig_port, pkt)
        #send_packet(self, ig_port, packet3)
        
        #time.sleep(1)
        #register_table = self.bfrt_info.table_get("SwitchIngress.test_monitor")
        #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.pkt_cnt_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.test_cnt")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.test_delta")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        #register_table = self.bfrt_info.table_get("SwitchIngress.c_pointer_reg_1")
        #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        #register_table = self.bfrt_info.table_get("SwitchIngress.c_pointer_reg_2")
        #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        #register_table = self.bfrt_info.table_get("SwitchIngress.c_pointer_reg_3")
        #resp = register_table.entry_get(
                    #self.target,
                    #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                    #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        #register_table = self.bfrt_info.table_get("SwitchIngress.c_pointer_reg_4")
        #resp = register_table.entry_get(
                    #self.target,
                    #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                    #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
            
        
        for i in range(4):
            register_table = self.bfrt_info.table_get("SwitchIngress.pipeTable1_1")
            resp = register_table.entry_get(
                    self.target,
                    [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    {"from_hw": True})
            data, _ = next(resp)
            data_dict = data.to_dict()
            print(data_dict)
        
        for i in range(4):
            register_table = self.bfrt_info.table_get("SwitchIngress.pipeTable1_2")
            resp = register_table.entry_get(
                    self.target,
                    [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    {"from_hw": True})
            data, _ = next(resp)
            data_dict = data.to_dict()
            print(data_dict)
        
        for i in range(4):
            register_table = self.bfrt_info.table_get("SwitchIngress.pipeTable2_1")
            resp = register_table.entry_get(
                    self.target,
                    [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    {"from_hw": True})
            data, _ = next(resp)
            data_dict = data.to_dict()
            print(data_dict)
        
        for i in range(4):
            register_table = self.bfrt_info.table_get("SwitchIngress.pipeTable2_2")
            resp = register_table.entry_get(
                    self.target,
                    [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    {"from_hw": True})
            data, _ = next(resp)
            data_dict = data.to_dict()
            print(data_dict)
        for i in range(1024):
            register_table = self.bfrt_info.table_get("SwitchIngress.deltaSketch2_1")
            resp = register_table.entry_get(
                    self.target,
                    [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    {"from_hw": True})
            data, _ = next(resp)
            data_dict = data.to_dict()
            print(data_dict)

    def verifyPackets(self):
        pass

    def runTest(self):
        self.runTestImpl()



