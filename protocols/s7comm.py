from collections import defaultdict
import ipaddress,re,string
from scapy.all import Ether,IP,TCP
from core.base import ProtocolPlugin
from core.context import now_iso
from core.stream_plugin import TcpStreamMixin
from core.stream_framers import tpkt_framer

ROS={1:"job",2:"ack",3:"ack_data",7:"userdata"};FUN={4:"read_var",5:"write_var",0x1a:"request_download",0x1b:"download_block",0x1c:"download_ended",0x1d:"start_upload",0x1e:"upload",0x1f:"end_upload",0x28:"pi_service",0x29:"plc_stop",0xf0:"setup_communication"}
def strings(data,n=4):
    out=[];cur=bytearray()
    for b in data:
        if chr(b) in string.printable and b not in {11,12}:cur.append(b)
        else:
            if len(cur)>=n:out.append(cur.decode("latin1","replace").strip())
            cur.clear()
    if len(cur)>=n:out.append(cur.decode("latin1","replace").strip())
    return [x for x in out if x]
class S7commPlugin(TcpStreamMixin,ProtocolPlugin):
    plugin_id="s7comm";display_name="Siemens S7comm";description="S7comm pasivo con reensamblado TPKT/COTP.";version="2.0";bpf_filter="tcp port 102";stream_framer=staticmethod(tpkt_framer)
    def __init__(self,config=None):super().__init__(config);self.init_tcp_streams();self.servers=defaultdict(self._new)
    @staticmethod
    def _new():return {"ip":None,"macs":set(),"clients":set(),"server_tsaps":set(),"rack":set(),"slot":set(),"pdu":set(),"ros":defaultdict(int),"fun":defaultdict(int),"strings":set(),"plus":False,"valid":0,"first":None,"last":None}
    def process_packet(self,p,context):
        if not p.haslayer(IP) or not p.haslayer(TCP):return
        ip,t=p[IP],p[TCP]
        if t.dport==102:server,client,d=ip.dst,ip.src,"c2s";mac=p[Ether].dst if p.haslayer(Ether) else None
        elif t.sport==102:server,client,d=ip.src,ip.dst,"s2c";mac=p[Ether].src if p.haslayer(Ether) else None
        else:return
        if context.network is not None:
            try:
                if ipaddress.ip_address(server) not in context.network:return
            except ValueError:return
        s=self.servers[server];s["ip"]=server;s["clients"].add(client)
        if mac:s["macs"].add(mac)
        stamp=now_iso();s["first"]=s["first"] or stamp;s["last"]=stamp
        _,frames=self.feed_tcp_stream(p)
        for tpkt in frames:self._parse(s,tpkt,d)
    def _parse(self,s,tpkt,d):
        cotp=tpkt[4:]
        if len(cotp)<2:return
        li=cotp[0];ptype=cotp[1]&0xf0
        if ptype in {0xe0,0xd0}:
            o=7
            while o+2<=len(cotp):
                code,n=cotp[o],cotp[o+1];o+=2;v=cotp[o:o+n];o+=n
                if len(v)<n:break
                if code==0xc2 and len(v)==2:s["server_tsaps"].add(v.hex());s["rack"].add((v[1]>>5)&7);s["slot"].add(v[1]&31)
            return
        if ptype!=0xf0:return
        app=cotp[li+1:]
        if not app:return
        if app[0]==0x72:s["plus"]=True;return
        if app[0]!=0x32 or len(app)<10:return
        ros=app[1];hlen=12 if ros in {2,3} else 10;pl=int.from_bytes(app[6:8],"big");dl=int.from_bytes(app[8:10],"big")
        if len(app)<hlen+pl+dl:return
        par=app[hlen:hlen+pl];data=app[hlen+pl:hlen+pl+dl];s["valid"]+=1;s["ros"][ROS.get(ros,hex(ros))]+=1
        if ros in {1,3} and par:
            f=par[0];s["fun"][FUN.get(f,hex(f))]+=1
            if f==0xf0 and len(par)>=8:s["pdu"].add(int.from_bytes(par[6:8],"big"))
        if ros==7 and d=="s2c":
            for x in strings(data):
                if len(x)<=96:s["strings"].add(x)
    @staticmethod
    def _identity(s):
        order=sorted(x for x in s["strings"] if re.search(r"6ES7\s*[0-9A-Z -]{5,}",x.upper())); products=sorted(x for x in s["strings"] if any(k in x.upper() for k in ("CPU","SIMATIC","S7-")));versions=sorted(x for x in s["strings"] if re.search(r"V\d+(?:\.\d+)+",x.upper()))
        return {"status":"ORDER_NUMBER_OBSERVED" if order else ("PRODUCT_OR_FAMILY_OBSERVED" if products else "S7COMM_CONFIRMED"),"vendor":"Siemens" if order or products else None,"order_numbers":order,"product_or_module":products,"firmware_or_versions":versions,"observed_strings":sorted(s["strings"]),"source":"passive_s7comm_userdata" if s["strings"] else "s7comm_traffic"}
    def finalize(self,context):
        out={ip:{"ip":ip,"port":102,"macs":sorted(s["macs"]),"clients":sorted(s["clients"]),"server_tsaps":sorted(s["server_tsaps"]),"rack_candidates":sorted(s["rack"]),"slot_candidates":sorted(s["slot"]),"negotiated_pdu_lengths":sorted(s["pdu"]),"rosctr_types":dict(sorted(s["ros"].items())),"functions":dict(sorted(s["fun"].items())),"s7comm_plus_seen":s["plus"],"valid_s7_pdus":s["valid"],"first_seen":s["first"],"last_seen":s["last"],"identification":self._identity(s)} for ip,s in sorted(self.servers.items())}
        context.protocol_results[self.plugin_id]={"passive_only":True,"server_count":len(out),"servers":out,"stream_statistics":self.tcp_stream_stats()}
