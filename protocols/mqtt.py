from collections import defaultdict
import ipaddress
from scapy.all import Ether, IP, TCP
from core.base import ProtocolPlugin
from core.context import now_iso
from core.stream_plugin import TcpStreamMixin
from core.stream_framers import mqtt_framer

PORTS={1883}; TYPES={1:"CONNECT",2:"CONNACK",3:"PUBLISH",4:"PUBACK",5:"PUBREC",6:"PUBREL",7:"PUBCOMP",8:"SUBSCRIBE",9:"SUBACK",10:"UNSUBSCRIBE",11:"UNSUBACK",12:"PINGREQ",13:"PINGRESP",14:"DISCONNECT",15:"AUTH"}
def vint(data, off=1):
    value=0; mult=1; n=0
    while n<4 and off+n<len(data):
        b=data[off+n]; value+=(b&127)*mult; n+=1
        if not b&128:return value,n
        mult*=128
    return None,0
def utf8(data, off):
    if off+2>len(data):return None,off
    n=int.from_bytes(data[off:off+2],"big"); off+=2
    if off+n>len(data):return None,off
    return data[off:off+n].decode("utf-8","replace"),off+n

class MqttPlugin(TcpStreamMixin, ProtocolPlugin):
    plugin_id="mqtt"; display_name="MQTT"; description="MQTT pasivo con reensamblado TCP."; version="2.0"; bpf_filter="tcp port 1883"
    stream_framer=staticmethod(mqtt_framer)
    def __init__(self,config=None):
        super().__init__(config); self.init_tcp_streams(); self.ports={int(x) for x in self.config.get("mqtt_ports",PORTS)}; self.brokers=defaultdict(self._new)
    @staticmethod
    def _new(): return {"ip":None,"ports":set(),"macs":set(),"clients":set(),"client_ids":set(),"versions":set(),"types":defaultdict(int),"published":set(),"connects":0,"connacks_ok":0,"first_seen":None,"last_seen":None}
    def process_packet(self,p,context):
        if not p.haslayer(IP) or not p.haslayer(TCP):return
        ip,t=p[IP],p[TCP]
        if t.dport in self.ports: broker,port,client,direction=ip.dst,int(t.dport),ip.src,"c2b"; mac=p[Ether].dst if p.haslayer(Ether) else None
        elif t.sport in self.ports: broker,port,client,direction=ip.src,int(t.sport),ip.dst,"b2c"; mac=p[Ether].src if p.haslayer(Ether) else None
        else:return
        if context.network is not None:
            try:
                if ipaddress.ip_address(broker) not in context.network:return
            except ValueError:return
        b=self.brokers[broker]; b["ip"]=broker;b["ports"].add(port);b["clients"].add(client)
        if mac:b["macs"].add(mac)
        s=now_iso();b["first_seen"]=b["first_seen"] or s;b["last_seen"]=s
        _,frames=self.feed_tcp_stream(p)
        for frame in frames:self._parse(b,frame,direction)
    def _parse(self,b,frame,direction):
        typ=frame[0]>>4; remain,n=vint(frame); body=frame[1+n:]
        b["types"][TYPES.get(typ,f"TYPE_{typ}")]+=1
        if typ==1 and direction=="c2b":
            name,o=utf8(body,0)
            if name not in {"MQTT","MQIsdp"} or o+4>len(body):return
            level=body[o];o+=4;b["connects"]+=1;b["versions"].add({3:"3.1",4:"3.1.1",5:"5.0"}.get(level,str(level)))
            if level==5:
                plen,pn=vint(body,o)
                if plen is None or o+pn+plen>len(body):return
                o+=pn+plen
            cid,_=utf8(body,o)
            if cid:b["client_ids"].add(cid)
        elif typ==2 and direction=="b2c" and len(body)>=2 and body[1]==0:b["connacks_ok"]+=1
        elif typ==3:
            topic,_=utf8(body,0)
            if topic:b["published"].add(topic)
    def finalize(self,context):
        out={ip:{"ip":ip,"ports":sorted(b["ports"]),"macs":sorted(b["macs"]),"clients":sorted(b["clients"]),"client_ids":sorted(b["client_ids"]),"protocol_versions":sorted(b["versions"]),"packet_types":dict(sorted(b["types"].items())),"topics_published":sorted(b["published"]),"connect_attempts":b["connects"],"successful_connacks":b["connacks_ok"],"first_seen":b["first_seen"],"last_seen":b["last_seen"]} for ip,b in sorted(self.brokers.items())}
        context.protocol_results[self.plugin_id]={"passive_only":True,"encrypted":False,"broker_count":len(out),"brokers":out,"stream_statistics":self.tcp_stream_stats()}
