# OpenVAS Vulnerability Test
# $Id: netware_ldap_search_request.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Netware LDAP search request
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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
tag_summary = "The server's directory base is set to NULL. This allows information to be 
enumerated without any prior knowledge of the directory structure.";

tag_solution = "Disable or restrict anonymous binds in LDAP if not required
";
if (description)
{
 script_id(12104);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Netware LDAP search request "; 
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Use LDAP search request to retrieve information from a Novell Netware Server";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "Netware";
 script_family(family);

 script_dependencies("ldap_detect.nasl");

 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://support.novell.com/cgi-bin/search/searchtid.cgi?/10077872.htm");
 exit(0);
}
#
# The script code starts here
#
include("misc_func.inc");
port = get_kb_item("Services/ldap");
if (!port) port = 389;
if ( ! get_port_state(port) ) exit(0);
flag = 0;

warning = string("
The server's directory base is set to NULL. This allows information to be 
enumerated without any prior knowledge of the directory struture.

The following information was pulled from the server via a LDAP request:\n");



senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0a, 
0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 
0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 
0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00
			);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:senddata);
buf = recv(socket:soc, length:4096);
close(soc);
version = string(buf);

if (buf == NULL) exit(0);

hbuf = hexstr(buf);


if ("Novell" >< buf) {
	hostname = strstr(hbuf, "4c44415020536572766572");
	hostname = hostname - strstr(hostname, "304f302b04075665");
	hostname = hex2raw(s:hostname);
	warning += string(hostname,"\n");
	flag = 1;
	}

if ("LDAP Server" >< buf) {
	version = strstr(hbuf, "4e6f76656c6c");
	version = version - strstr(version, "300d");
	version = hex2raw(s:version);
	warning += string(version);
	flag = 1;
	}

if (flag == 1) {
	warning += 
string("

Solution: Disable or restrict anonymous binds in LDAP if not required
See also: http://support.novell.com/cgi-bin/search/searchtid.cgi?/10077872.htm
Risk Factor: Medium");
security_warning(port:port, data:warning);
}

