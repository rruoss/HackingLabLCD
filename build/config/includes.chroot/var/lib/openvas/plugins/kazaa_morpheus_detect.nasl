# OpenVAS Vulnerability Test
# $Id: kazaa_morpheus_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Kazaa / Morpheus Client Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com> 
# Copyright (C) 2001 SecuriTeam
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
# 2002-06-08 Michel Arboi
# The script did not detect the latest versions of the Kazaa software.
# The session is:
# GET / HTTP/1.0
# 
# HTTP/1.0 404 Not Found
# X-Kazaa-Username: xxxx
# X-Kazaa-Network: KaZaA
# X-Kazaa-IP: 192.168.192.168:1214
# X-Kazaa-SupernodeIP: 10.10.10.10:1214

include("revisions-lib.inc");
tag_summary = "The Kazaa / Morpheus HTTP Server is running.
This server is used to provide other clients with a
connection point. However, it also exposes sensitive system files.";

tag_solution = "Currently there is no way to limit this exposure.
Filter incoming traffic to this port.

More Information: http://www.securiteam.com/securitynews/5UP0L2K55W.html";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(10751);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Kazaa / Morpheus Client Detection";
 script_name(name);
 
 

 script_description(desc);
 
 summary = "Kazaa / Morpheus Client Detect";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 family = "Peer-To-Peer File Sharing";
 script_family(family);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 1214);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:1214);
foreach port (ports)
{
  resultrecv = get_http_banner(port: port);
   # if (egrep(pattern:"^Server: KazaaClient", string:resultrecv))
   if ("X-Kazaa-Username: " >< resultrecv)
   {
    buf = strstr(resultrecv, "X-Kazaa-Username: ");
    buf = buf - "X-Kazaa-Username: ";
    subbuf = strstr(buf, string("\r\n"));
    buf = buf - subbuf;
    username = buf;

    buf = "Remote host reported that the username used is: ";
    buf = buf + username;

    set_kb_item(name:"kazaa/username", value:username);
    report = string(desc, "\n\n", buf);
    security_hole(data:report, port:port);
   }
}
 
