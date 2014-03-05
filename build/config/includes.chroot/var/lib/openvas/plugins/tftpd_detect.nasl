# OpenVAS Vulnerability Test
# $Id: tftpd_detect.nasl 43 2013-11-04 19:51:40Z jan $
# Description: TFTP detection
#
# Authors:
# Vlatko Kosturjak
#
# Copyright:
# Copyright (C) 2009 Vlatko Kosturjak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host has TFTP server running.

Description :

The remote host has TFTP server running. TFTP stands 
for Trivial File Transfer Protocol.";

tag_solution = "Disable TFTP server if not used.";

if (description)
{
 script_id(80100);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-04 10:25:48 +0100 (Wed, 04 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description( desc);
 script_copyright("Copyright (C) 2009 Vlatko Kosturjak");
 script_name( "TFTP detection");
 script_category(ACT_GATHER_INFO);
 script_family( "Service detection");
 script_summary( "Detects TFTP server");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('misc_func.inc');
include('global_settings.inc');

foundtftp=0;

# taken from tftpd_dir_trav.nasl, adapted a bit
function tftp_grab(port, file, mode)
{
 local_var      req, rep, sport, ip, u, filter, data, i;

 req = '\x00\x01'+file+'\0'+mode+'\0';

 sport = rand() % 64512 + 1024;

 if(TARGET_IS_IPV6()) {

   IP6_v = 0x60;
   IP6_P = IPPROTO_UDP;
   IP6_HLIM = 0x40;
   ip6_packet = forge_ipv6_packet(ip6_v: IP6_v,
                                  ip6_p: IP6_P,
                                  ip6_plen: 20,
                                  ip6_hlim: IP6_HLIM,
                                  ip6_src: this_host(),
                                  ip6_dst: get_host_ip());

   udppacket = forge_udp_v6_packet(ip6: ip6_packet,
                                   uh_sport: sport,
                                   uh_dport: port,
                                   uh_ulen: 8 + strlen(req),
                                   data: req);

   filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and dst host ' + this_host();  

   for(i=0; i<2; i++) { 
  
     rpkt = send_v6packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if(!rpkt)continue;

     data = get_udp_v6_element(udp:rpkt, element:"data");
     if(!data)continue;

     if (data[0] == '\0') {
       if (data[1] == '\x03' || data[1] =='\x05') {
         foundtftp=1;
       }
     } 
  }     

 } else {

  ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, 
         ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
         ip_src: this_host());
                     
  u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

  filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

  data = NULL;
  for (i = 0; i < 2; i ++)       # Try twice
  {
   rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
   if(rep)
   {
    if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
    data = get_udp_element(udp: rep, element:"data");
    if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
    if (data[0] == '\0')
    {
 	 if (data[1] == '\x03' || data[1] =='\x05') {
		 foundtftp=1;
	 }
    }
    else
      return NULL;
   }
  }
 }
  return NULL;
}

port=69;
if(!(get_udp_port_state(69)))exit(0);

rndfile="nonexistant-"+rand_str();

# test valid modes according to RFC-783 
tftp_grab (port:port, file:rndfile, mode:"netascii");

if (foundtftp!=1) { 
  tftp_grab (port:port, file:rndfile, mode:"octet");
}  

if (foundtftp!=1) {
  tftp_grab (port:port, file:rndfile, mode:"mail");
}  

if (foundtftp==1) {
	register_service(port: port, ipproto: "udp", proto: "tftp");
	security_note(port:port, proto:"udp");
}

