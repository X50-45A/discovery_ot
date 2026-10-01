import unittest
from scapy.all import IP, TCP, Raw
from core.tcp_reassembly import TcpReassembler
from core.stream_framers import StreamBuffer, modbus_tcp_framer, mqtt_framer, tls_record_framer, tpkt_framer


def packet(seq, payload=b"", flags="PA", sport=40000, dport=502):
    p=IP(src="10.0.0.1",dst="10.0.0.2")/TCP(sport=sport,dport=dport,seq=seq,flags=flags)
    return p/Raw(payload) if payload else p

class ReassemblyTests(unittest.TestCase):
    def test_ordered_and_retransmission(self):
        r=TcpReassembler();self.assertEqual(r.feed(packet(100,b"abc")).data,b"abc");self.assertEqual(r.feed(packet(103,b"def")).data,b"def");self.assertEqual(r.feed(packet(100,b"abc")).data,b"")
    def test_out_of_order_before_gap(self):
        r=TcpReassembler();self.assertEqual(r.feed(packet(100,b"abc")).data,b"abc");self.assertEqual(r.feed(packet(106,b"ghi")).data,b"");self.assertEqual(r.feed(packet(103,b"def")).data,b"defghi")
    def test_overlap(self):
        r=TcpReassembler();self.assertEqual(r.feed(packet(100,b"abcdef")).data,b"abcdef");self.assertEqual(r.feed(packet(103,b"defghi")).data,b"ghi")
    def test_modbus_fragmented(self):
        adu=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01";s=StreamBuffer(modbus_tcp_framer);self.assertEqual(s.feed(adu[:5]),[]);self.assertEqual(s.feed(adu[5:]),[adu])
    def test_mqtt_two_frames(self):
        a=b"\xc0\x00";b=b"\xd0\x00";s=StreamBuffer(mqtt_framer);self.assertEqual(s.feed(a+b),[a,b])
    def test_tls_fragmented(self):
        rec=b"\x16\x03\x03\x00\x04test";s=StreamBuffer(tls_record_framer);self.assertEqual(s.feed(rec[:3]),[]);self.assertEqual(s.feed(rec[3:]),[rec])
    def test_tpkt_fragmented(self):
        tpkt=b"\x03\x00\x00\x07\x02\xf0\x80";s=StreamBuffer(tpkt_framer);self.assertEqual(s.feed(tpkt[:4]),[]);self.assertEqual(s.feed(tpkt[4:]),[tpkt])

if __name__=="__main__":unittest.main()
