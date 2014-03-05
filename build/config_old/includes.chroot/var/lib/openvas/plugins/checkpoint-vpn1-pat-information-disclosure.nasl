# OpenVAS Vulnerability Test
# $Id: checkpoint-vpn1-pat-information-disclosure.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Checkpoint VPN-1 PAT information disclosure
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Fixes (+note about FP): Vlatko Kosturjak <kost@linux.hr>
#
# Copyright:
# Copyright (c) 2008 Tim Brown and Portcullis Computer Security Ltd
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_summary = "Checkpoint VPN-1 PAT information disclosure

By sending crafted packets to ports on the firewall which are mapped by port address translation (PAT) to ports on internal devices, information about the internal network may be disclosed in the resulting ICMP error packets. Port 18264/tcp on the firewall is typically configured in such a manner, with packets to this port being rewritten to reach the firewall management server.  For example, the firewall fails to correctly sanitise the encapsulated IP headers in ICMP time-to-live exceeded packets resulting in internal IP addresses being disclosed.

On the following platforms, we recommend you mitigate in the described manner:
Checkpoint VPN-1 R55
Checkpoint VPN-1 R65

We recommend you mitigate in the following manner:
Disable any implied rules and only open ports for required services
Filter outbound ICMP time-to-live exceeded packets";

tag_solution = "We are not aware of a vendor approved solution at the current time.


False positive:
This could be false positive alert. Try running same scan against single host 
where this vulnerability is reported.";


if (description)
{
	script_id(80096);
	script_version("$Revision: 16 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2008-11-05 16:59:22 +0100 (Wed, 05 Nov 2008)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
	script_cve_id("CVE-2008-5849");
	name = "Checkpoint VPN-1 PAT information disclosure";
	script_name(name);
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
	script_description(desc);
	summary = "Determines whether Checkpoint VPN-1 is disclosing information about the internal network via PAT";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	family = "Firewalls";
	script_family(family);
	copyright = "(c) Tim Brown and Portcullis Computer Security Ltd, 2008";
	script_copyright(copyright);
	script_require_ports(264);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.portcullis-security.com/293.php");
	exit(0);
}

include("cpe.inc");
include("host_details.inc");

if(TARGET_IS_IPV6())exit(0);

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80096";
SCRIPT_DESC = "Checkpoint VPN-1 PAT information disclosure";

## functions for script
function packet_construct(_ip_src, _ip_ttl)
{
	_ip_id = rand() % 65535;
	_th_sport = (rand() % 64000) + 1024;
	_ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:_ip_id, ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, ip_src:_ip_src, ip_ttl:_ip_ttl);
	_tcp = forge_tcp_packet(ip:_ip, th_sport:_th_sport, th_dport:18264, th_flags:TH_SYN, th_seq:_ip_ttl, th_ack:0, th_x2:0, th_off:5, th_win:2048, th_urp:0);
	return _tcp;
}

function packet_parse(_icmp, _ip_dst, _ttl)
{
	_ip = get_icmp_element(icmp:_icmp, element:"data");
	_ip_p = get_ip_element(ip:_ip, element:"ip_p");
	_ip_dst2 = get_ip_element(ip:_ip, element:"ip_dst");
	_ip_hl = get_ip_element(ip:_ip, element:"ip_hl");
	_tcp = substr(_ip, (_ip_hl * 4), strlen(_ip));
	_ih_dport = (ord(_tcp[2]) * 256) + ord(_tcp[3]);
	_data="";
	if ((_ip_p == IPPROTO_TCP) && (_ip_dst2 != _ip_dst) && (_ih_dport == 18264))
	{
		_data = "Internal IP disclosed: " + _ip_dst2 + " (ttl: "+_ttl+")
";
		set_kb_item(name:"Checkpoint/Manager/ipaddress", value:_ip_dst2);
                register_host_detail(name:"App", value:"cpe:/a:checkpoint:vpn-1", nvt:SCRIPT_OID, desc:SCRIPT_DESC);

	}
	return _data;
}

## start script
if (islocalhost())
{
	exit(0);
}
port=264;
if (!get_port_state(port)) 
{
	exit(0);
}

sourceipaddress = this_host();
destinationipaddress = get_host_ip();
packetfilter = "dst host " + sourceipaddress + " and icmp and (icmp[0]=11)";
reportout="";
for (ttl = 1; ttl <= 50; ttl ++)
{
	requestpacket = packet_construct(_ip_src:sourceipaddress, _ip_ttl:ttl);
	responsepacket = send_packet(requestpacket, pcap_active:true, pcap_filter:packetfilter, pcap_timeout:1);
	if (responsepacket)
	{
		reportdata=packet_parse(_icmp:responsepacket, _ip_dst:destinationipaddress, _ttl:ttl);
		reportout=reportout+reportdata;
	}
}

if (reportout != "") {
	reportheading="

Disclosures:
";
	wholereport=desc + reportheading + reportout;
	security_warning(protocol:"tcp", port:18264, data:wholereport);
}
