# OpenVAS Vulnerability Test
# $Id: check_dns_tcp.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DNS Server on UDP and TCP
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
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
tag_summary = "A DNS server is running on this port but 
it only answers to UDP requests.
This means that TCP requests are blocked by a firewall.

This configuration is incorrect: TCP might be used by any 
request, it is not restricted to zone transfers.
Read RFC1035 or STD0013 for more information.";

# This is not really a security check.
# See STD0013

if(description)
{
 script_id(18356);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "DNS Server on UDP and TCP";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Checks if the remote DNS servers answers on TCP too";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);

 script_dependencies('external_svc_ident.nasl', 'dns_server.nasl');
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "General";
 script_family(family);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');

if (! thorough_tests && report_verbosity < 2)
{
 debug_print('will only run in "Verbose report" or "Thorough tests" mode\n');
 exit(0);
}


port = get_kb_item('Services/udp/dns');
if (! port) exit(0);

if (! get_udp_port_state(port)) exit(0);	# Only on TCP?

if (verify_service(port: port, ipproto: 'tcp', proto: 'dns')) exit(0);
soc = open_sock_tcp(port);
if (! soc) security_note(port);
else
{
 close(soc);
 if (get_port_state(port))
   register_service(port: port, proto: 'dns');
}


