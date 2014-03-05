###############################################################################
# OpenVAS Vulnerability Test
#
# traceroute
#
# Authors:
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com
# 2006/06/10: Improved to handle up to 3 consecutive missing nodes.
#
# 2010/07/10 Complete rewrite  by Michael Meyer <michael.meyer@greenbone.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Block unwanted packets from escaping your network.";
tag_summary = "A traceroute from the scanning server to the target system was
conducted. This traceroute is provided primarily for informational
value only. In the vast majority of cases, it does not represent a
vulnerability. However, if the displayed traceroute contains any
private addresses that should not have been publicly visible, then you
have an issue you need to correct.";


if(description)
{
 script_id(51662);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-08 19:27:45 +0200 (Thu, 08 Jul 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Traceroute");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_summary("Traceroute");
 script_description(desc);
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("General");
 script_dependencies("ping_host.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");


function IP_IS_IPV6(ip) {
  if(":" >< ip) {
    return TRUE;
   }
  return FALSE;
}

function get_filter(ipsrc,port,sport,ipdst) {

  local_var ipsrc, port, sport, ipdst;

  return "((dst host " + ipsrc + " and icmp and ((icmp[0]=11) or (icmp[0]=3) or (icmp[0]=0))) or (src host " + ipdst + " and tcp and (tcp[0:2]=" + port + " and tcp[2:2]=" + sport + ")))";

}

function read_packet(packet) {

  local_var ip_hl, get_ip_elementip_dst, port,packet, _code, _type;

  _IPP = get_ip_element(ip:packet, element:"ip_p");
  ip_hl = get_ip_element(ip:packet, element:"ip_hl");
  _ip_src = get_ip_element(ip:packet, element:"ip_src");

  if(_IPP == IPPROTO_ICMP) {

    ip = substr(packet, ip_hl*4+8, ip_hl*4+8+20);
    ip_dst = get_ip_element(ip:ip, element:"ip_dst");
    id  = get_ip_element(ip:ip, element:"ip_id");

    if(_ip_src == ipdst) {
      target_answer = TRUE;
      return TRUE; 
    }  

    if (id != ipid || !id) { return FALSE; }

    if(ip_dst == ipdst) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }
  
  else {

    d = substr(packet, ip_hl*4, strlen(packet));
    p = ord(d[2])*256+ord(d[3]);
    ip = substr(packet, ip_hl*4+8, ip_hl*4+8+20);

    if(_ip_src == ipdst && p == sport)  {
      target_answer = TRUE;
      return TRUE;
    }   
    else {
      return FALSE;
    }  
  }

 return FALSE;

}

if(islocalhost()) {
 
   h = get_host_ip();
   r = string("Here is the route from ",h, " to ", h,":\n\n",h,"\n");
   set_kb_item(name:string("traceroute/hops"),value:1);
   set_kb_item(name:string("traceroute/route"),value:h);
   register_host_detail(name:"traceroute", value:h, nvt:"1.3.6.1.4.1.25623.1.0.51662", desc:"Traceroute");
   log_message(port:0,data:r);
   exit(0);
}  

port = get_host_open_port();
if(!port)port = 80;

register_hd = TRUE;

e_count = 0;
ttl = 2;
ipsrc = this_host();
ipdst = get_host_ip();
ipid = rand()%65535;

if(IP_IS_IPV6(ip:ipdst))exit(0);

while(TRUE) {

   for (i=0; i < 2; i++) {

     sport = rand()%64000+1024;

     if(e_count >= 1) {
       IPPROTO = IPPROTO_TCP;
     } 
     else {
       IPPROTO = IPPROTO_ICMP;
     }

     ippkt = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_id:ipid, ip_len:20, ip_off:0, ip_p:IPPROTO,ip_src:ipsrc, ip_ttl:ttl);

     if(e_count >= 1) { 
       pkt = forge_tcp_packet(ip:ippkt, th_sport:sport, th_dport:port, th_flags:TH_SYN, th_seq:ttl, th_ack:0, th_x2:0, th_off:5, th_win:2048, th_urp:0);
     } 
     else {  
       pkt = forge_icmp_packet(ip:ippkt, icmp_type:8, icmp_code:0, icmp_seq:ttl, icmp_id:ipid);
     }  
     
     pcapfil = get_filter(ipsrc:ipsrc,port:port,sport:sport,ipdst:ipdst); 
     response = send_packet(pkt, pcap_active:TRUE, pcap_filter:pcapfil, pcap_timeout:1);

     type = get_icmp_element(icmp:response,element:"icmp_type");
     code = get_icmp_element(icmp:response,element:"icmp_code");
     if(response) {
       IPP  = get_ip_element(ip:response, element:"ip_p");
     }  
     
     if(response && IPP == IPPROTO_ICMP) {
       if(((type != 11) && (type != 0 && code != 0)) && (type != "" && code != "")) { break;}
     }  

     while(response) {

       if(!read_packet(packet:response)) {
         response = pcap_next(pcap_filter:filter, timeout:1);
       } else {
         break;
       }

     }

     if(response) {

       response_src = get_ip_element(ip:response, element:"ip_src");
       if(response_src == ipdst) { target_answer = TRUE; break; }
       if(!ereg(pattern:response_src, string:hops)) {
         hops += string(response_src,",");
         hops_count++;
       } else {
         seen++;
       }	 
       error = 0;
       e_count = 0;
       break;

     } else {

       if(e_count > 1) { error++; break; }
       e_count++;

     }

     if(isnull(type) && hops_count > 0 && !response && i==1) { hops_count++; hops += string("* * *,"); break;}

   }

  if(error > 3 || seen > 3 || ttl >= 30 || target_answer || (!isnull(type) && (type != 11 && type != 0)))break;
  ttl++;
  usleep(100000);
}

hops_count += 2;

hops_report  = string("Here is the route from ",ipsrc, " to ", ipdst,":\n\n");

if(hops_count == 2 && error > 3) {
  ipdst = "?";
  register_hd = FALSE;
}  

hops = string(ipsrc,",",hops,ipdst);

set_kb_item(name:string("traceroute/hops"),value:hops_count);
set_kb_item(name:string("traceroute/route"),value:hops);

if (register_hd)
  register_host_detail(name:"traceroute", value:hops, nvt:"1.3.6.1.4.1.25623.1.0.51662", desc:"Traceroute");

hops_report += ereg_replace(string:hops, pattern:",",replace:string("\n"));
hops_report += string("\n");

log_message(port:0,data:hops_report);
exit(0);

