from collections import defaultdict
import ipaddress
from scapy.all import Ether, IP, TCP
from core.base import ProtocolPlugin
from core.context import now_iso
from core.stream_plugin import TcpStreamMixin
from core.stream_framers import tls_record_framer

class MqttsPlugin(TcpStreamMixin,ProtocolPlugin):
    plugin_id="mqtts";display_name="MQTTS";description="Probable MQTT sobre TLS con reensamblado de registros TLS.";version="2.0";bpf_filter="tcp port 8883"
    stream_framer=staticmethod(tls_record_framer)
    def __init__(self,config=None):
        super().__init__(config);self.init_tcp_streams();self.ports={int(x) for x in self.config.get("mqtts_ports",{8883})};self.brokers=defaultdict(self._new)
    @staticmethod
    def _new():return {"ip":None,"ports":set(),"macs":set(),"clients":set(),"versions":set(),"record_types":defaultdict(int),"sni":set(),"client_hello":0,"server_hello":0,"application":0,"first_seen":None,"last_seen":None}
    def process_packet(self,p,context):
        if not p.haslayer(IP) or not p.haslayer(TCP):return
        ip,t=p[IP],p[TCP]
        if t.dport in self.ports:broker,port,client,d=ip.dst,int(t.dport),ip.src,"c2b";mac=p[Ether].dst if p.haslayer(Ether) else None
        elif t.sport in self.ports:broker,port,client,d=ip.src,int(t.sport),ip.dst,"b2c";mac=p[Ether].src if p.haslayer(Ether) else None
        else:return
        if context.network is not None:
            try:
                if ipaddress.ip_address(broker) not in context.network:return
            except ValueError:return
        b=self.brokers[broker];b["ip"]=broker;b["ports"].add(port);b["clients"].add(client)
        if mac:b["macs"].add(mac)
        s=now_iso();b["first_seen"]=b["first_seen"] or s;b["last_seen"]=s
        _,frames=self.feed_tcp_stream(p)
        for r in frames:self._parse(b,r,d)
    def _parse(self,b,r,d):
        typ=r[0];ver=int.from_bytes(r[1:3],"big");frag=r[5:];b["versions"].add(f"0x{ver:04X}");b["record_types"][{20:"change_cipher_spec",21:"alert",22:"handshake",23:"application_data",24:"heartbeat"}.get(typ,str(typ))]+=1
        if typ==23:b["application"]+=1
        if typ!=22:return
        o=0
        while o+4<=len(frag):
            ht=frag[o];n=int.from_bytes(frag[o+1:o+4],"big");body=frag[o+4:o+4+n]
            if len(body)<n:return
            if ht==1 and d=="c2b":b["client_hello"]+=1;s=self._sni(body);b["sni"].add(s) if s else None
            elif ht==2 and d=="b2c":b["server_hello"]+=1
            o+=4+n
    @staticmethod
    def _sni(body):
        if len(body)<34:return None
        o=34
        if o>=len(body):return None
        o+=1+body[o]
        if o+2>len(body):return None
        n=int.from_bytes(body[o:o+2],"big");o+=2+n
        if o>=len(body):return None
        o+=1+body[o]
        if o+2>len(body):return None
        total=int.from_bytes(body[o:o+2],"big");o+=2;end=min(o+total,len(body))
        while o+4<=end:
            et=int.from_bytes(body[o:o+2],"big");n=int.from_bytes(body[o+2:o+4],"big");v=body[o+4:o+4+n]
            if o+4+n>end:return None
            if et==0 and len(v)>=5:
                pos=2
                while pos+3<=len(v):
                    nt=v[pos];ln=int.from_bytes(v[pos+1:pos+3],"big");pos+=3
                    if pos+ln>len(v):return None
                    if nt==0:return v[pos:pos+ln].decode("idna","replace")
                    pos+=ln
            o+=4+n
        return None
    def finalize(self,context):
        out={ip:{"ip":ip,"ports":sorted(b["ports"]),"macs":sorted(b["macs"]),"clients":sorted(b["clients"]),"tls_record_versions":sorted(b["versions"]),"sni_names":sorted(b["sni"]),"record_types":dict(sorted(b["record_types"].items())),"client_hellos":b["client_hello"],"server_hellos":b["server_hello"],"application_data_records":b["application"],"mqtt_payload_visible":False,"first_seen":b["first_seen"],"last_seen":b["last_seen"]} for ip,b in sorted(self.brokers.items())}
        context.protocol_results[self.plugin_id]={"passive_only":True,"encrypted":True,"broker_count":len(out),"brokers":out,"stream_statistics":self.tcp_stream_stats(),"warning":"TLS on port 8883 is strong evidence, not cryptographic proof of MQTT inside TLS."}
