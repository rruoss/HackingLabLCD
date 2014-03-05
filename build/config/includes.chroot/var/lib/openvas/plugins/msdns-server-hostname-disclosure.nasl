# OpenVAS Vulnerability Test
# $Id: msdns-server-hostname-disclosure.nasl 43 2013-11-04 19:51:40Z jan $
# Description: Microsoft DNS server internal hostname disclosure detection
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (c) 2009 Tim Brown
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
tag_summary = "Microsoft DNS server internal hostname disclosure detection

Microsoft DNS server may disclose the internal hostname of the server in response to requests for the hardcoded zones 0.in-addr.arpa and 255.in-addr.arpa.

On the following platforms, we recommend you resolve in the described manner:
All default Microsoft DNS server configurations";

tag_solution = "http://support.microsoft.com/default.aspx?id=198410";

if (description)
{
	script_id(100950);
	script_version("$Revision: 43 $");
	script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
	script_tag(name:"creation_date", value:"2009-07-10 19:42:14 +0200 (Fri, 10 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
	name = "Microsoft DNS server internal hostname disclosure detection";
	script_name(name);
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

	script_description(desc);
	summary = "Determines whether Microsoft DNS server is accessible and whether it discloses the internal hostname";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	family = "Service detection";
	script_family(family);
	script_copyright("(c) Tim Brown, 2009");
        script_require_udp_ports(53);
	# script_require_udp_ports(53);
	script_require_keys("DNS/udp/53");
	script_dependencies("dns_server.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.openvas.org/blog.php?id=31");
	exit(0);
}

function packet_construct(_dns_zone) {
	# query _dns_zone/SOA/IN
	_dns_query = raw_string(0x8d, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
	foreach _dns_node (split(_dns_zone, sep:".", keep:FALSE)) {
		_dns_query += raw_string(strlen(_dns_node)) + _dns_node;
	}
	_dns_query += raw_string(0x00, 0x00, 0x06, 0x00, 0x01);
	return _dns_query;
}

function packet_parse(_dns_query, _dns_response) {
	# for a valid SOA response:
	# TXID 2
	# Flags 2 - 2 is server failure, 3 is no such name and 5 is refused
	# Questions 2
	# Answers 2
	# Authority 2
	# Additional 2
	# DNS query x + 2 (length encoded, with null)
	# Type 2
	# Class 2
	# Name 2
	# Type 2
	# Class 2
	# TTL 4
	# Data length 2
	# DNS server x + 2 (length encoded, with null)
	# Email address x + 3 (length encoded with 2 trailing bytes?)
	# Serial 4
	# Refresh interval 4
	# Retry interval
	# Expiry limit
	# Minimum TTL
	# is it a valid response?
	if ((_dns_response != "") && ((ord(_dns_response[3]) & 2) != 2) && ((ord(_dns_response[3]) & 3) != 3) && ((ord(_dns_response[3]) & 5) != 5)) {
		_hostdata = substr(_dns_response, 12 + strlen(_dns_query) + 18);
		_hostname = "";
		# is it using DNS compression with a pointer offset to the DNS query?
		if ((ord(_hostdata[0]) != 192) && (ord(_hostdata[1]) != 12)) {
			_counter1 = 0;
			while (ord(_hostdata[_counter1]) != 0) {
				for (_counter2 = 1; _counter2 <= ord(_hostdata[_counter1]); _counter2 ++) {
					_hostname += _hostdata[_counter1 + _counter2];
				}
				_counter1 += _counter2;
				if (ord(_hostdata[_counter1]) != 0) {
					_hostname += ".";
				}
			}
			if ("localhost" >!< _hostname) {
				_data = "Microsoft DNS server seems to be running on this port.
	
Internal hostname disclosed (" + _dns_query + "/SOA/IN): " + _hostname;
				security_note(protocol:udp, port:53, data:_data);
				set_kb_item(name:"DNS/udp/53/hostname", value:_hostname);
			}
		}
	}
}

portnumber = 53;
if (!get_udp_port_state(portnumber)) {
	exit(0);
}
socket = open_sock_udp(portnumber);
if (!socket) {
	exit(0);
}
foreach dns_zone (make_list("0.in-addr.arpa", "255.in-addr.arpa")) {
	requestpacket = packet_construct(_dns_zone:dns_zone);
	send(socket:socket, data:requestpacket);
	responsepacket = recv(socket:socket, length:4096);
	close(socket);
	packet_parse(_dns_query:dns_zone, _dns_response:responsepacket);
}
