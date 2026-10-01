from collections import defaultdict
import ipaddress,math
from scapy.all import Ether,IP,TCP,UDP
from core.base import ProtocolPlugin
from core.context import now_iso
from core.stream_plugin import TcpStreamMixin
from core.stream_framers import dnp3_framer

APP={1:"read",2:"write",3:"select",4:"operate",5:"direct_operate",6:"direct_operate_no_ack",0x0d:"cold_restart",0x0e:"warm_restart",0x14:"enable_unsolicited",0x15:"disable_unsolicited",0x20:"authentication_request",0x81:"response",0x82:"unsolicited_response",0x83:"authentication_response"}
class Dnp3Plugin(TcpStreamMixin,ProtocolPlugin):
    plugin_id="dnp3";display_name="DNP3";description="DNP3 TCP/UDP pasivo con reensamblado TCP y transporte DNP3.";version="2.0";bpf_filter="tcp port 20000 or udp port 20000";stream_framer=staticmethod(dnp3_framer)
    def __init__(self,config=None):super().__init__(config);self.init_tcp_streams();self.outstations=defaultdict(self._new);self.fragments=defaultdict(bytearray)
    @staticmethod
    def _new():return {"ip":None,"ports":set(),"transports":set(),"macs":set(),"masters":set(),"addr":set(),"master_addr":set(),"functions":defaultdict(int),"groups":defaultdict(int),"valid":0,"first":None,"last":None}
    def process_packet(self,p,context):
        if not p.haslayer(IP):return
        ip=p[IP]
        if p.haslayer(TCP):t=p[TCP];transport="tcp"
        elif p.haslayer(UDP):t=p[UDP];transport="udp"
        else:return
        if t.dport==20000:server,port,master,d=ip.dst,20000,ip.src,"m2o";mac=p[Ether].dst if p.haslayer(Ether) else None
        elif t.sport==20000:server,port,master,d=ip.src,20000,ip.dst,"o2m";mac=p[Ether].src if p.haslayer(Ether) else None
        else:return
        if context.network is not None:
            try:
                if ipaddress.ip_address(server) not in context.network:return
            except ValueError:return
        o=self.outstations[server];o["ip"]=server;o["ports"].add(port);o["transports"].add(transport);o["masters"].add(master)
        if mac:o["macs"].add(mac)
        s=now_iso();o["first"]=o["first"] or s;o["last"]=s
        if transport=="tcp":key,frames=self.feed_tcp_stream(p)
        else:key=(4,ip.src,int(t.sport),ip.dst,int(t.dport));buf=bytearray(bytes(t.payload));frames=dnp3_framer(buf).frames
        for frame in frames:self._link(o,frame,d,key)
    @staticmethod
    def _user(frame):
        length=frame[2]-5;raw=frame[10:];out=bytearray();pos=0;remain=length
        while remain:
            n=min(16,remain)
            if pos+n+2>len(raw):return b""
            out.extend(raw[pos:pos+n]);pos+=n+2;remain-=n
        return bytes(out)
    def _link(self,o,frame,d,key):
        if len(frame)<10 or frame[:2]!=b"\x05\x64":return
        dst=int.from_bytes(frame[4:6],"little");src=int.from_bytes(frame[6:8],"little")
        if d=="o2m":o["addr"].add(src);o["master_addr"].add(dst)
        else:o["addr"].add(dst);o["master_addr"].add(src)
        user=self._user(frame);o["valid"]+=1
        if not user:return
        tr=user[0];fir=bool(tr&0x40);fin=bool(tr&0x80);seq=tr&0x3f;fragment_key=(key,src,dst)
        if fir:self.fragments[fragment_key]=bytearray()
        if fragment_key not in self.fragments:return
        self.fragments[fragment_key].extend(user[1:])
        if not fin:return
        app=bytes(self.fragments.pop(fragment_key));
        if len(app)<2:return
        fc=app[1];o["functions"][APP.get(fc,hex(fc))]+=1;cursor=4 if fc in {0x81,0x82,0x83} and len(app)>=4 else 2
        if len(app)>=cursor+3:o["groups"][str(app[cursor])]+=1
    def finalize(self,context):
        out={ip:{"ip":ip,"ports":sorted(o["ports"]),"transports":sorted(o["transports"]),"macs":sorted(o["macs"]),"masters":sorted(o["masters"]),"dnp3_addresses":sorted(o["addr"]),"master_dnp3_addresses":sorted(o["master_addr"]),"application_functions":dict(sorted(o["functions"].items())),"object_groups":dict(sorted(o["groups"].items())),"valid_link_frames":o["valid"],"first_seen":o["first"],"last_seen":o["last"],"identification":{"status":"DNP3_CONFIRMED","source":"dnp3_traffic"}} for ip,o in sorted(self.outstations.items())}
        context.protocol_results[self.plugin_id]={"passive_only":True,"outstation_count":len(out),"outstations":out,"stream_statistics":self.tcp_stream_stats(),"pending_dnp3_fragments":len(self.fragments)}
