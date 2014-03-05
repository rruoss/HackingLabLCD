# OpenVAS Vulnerability Test
# $Id: ntds_get_info.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Use LDAP search request to retrieve information from NT Directory Services
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# changes by rd: minor wording in the description
#
# Copyright:
# Copyright (C) David Kyger
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
tag_solution = "If pre-Windows 2000 compatibility is not required, remove 
pre-Windows 2000 compatibility as follows :

- start cmd.exe
- execute the command :
  net localgroup  'Pre-Windows 2000 Compatible Access' everyone /delete
- restart the remote host";

tag_summary = "It is possible to disclose LDAP information.

Description :

The directory base of the remote server is set to NULL. This allows information 
to be enumerated without any prior knowledge of the directory structure.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_id(12105);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"2.0");
 script_tag(name:"cvss_base_vector", value:"AV:R/AC:L/Au:N/C:P/A:N/I:N/B:N");
 script_tag(name:"risk_factor", value:"Low");
 
 name = "Use LDAP search request to retrieve information from NT Directory Services";

 script_name(name);

 script_description(desc);
 summary = "Use LDAP search request to retrieve information from NT Directory Services";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 script_family("Remote file access");

 script_dependencies("ldap_detect.nasl");
 script_require_ports("Services/ldap", 389);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}
#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if ( ! get_port_state(port) ) exit(0);

senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 
0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 
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
	if ("NTDS" >< buf) {
		hbuf = hexstr(buf);
		ntdsinfo = strstr(hbuf, "4e54445320");
		ntdsinfo = ntdsinfo - strstr(ntdsinfo, "308400");
		ntdsinfo = hex2raw(s:ntdsinfo);
		warning  = warning + string(ntdsinfo,"\n\n");

		report = string (desc,
				"\n\nPlugin output :\n\n",
				"The following information was pulled from the server via a LDAP request:\n",
				warning);

		security_note(port:port, data:report);
	}
