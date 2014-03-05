# OpenVAS Vulnerability Test
# $Id: mediahouse_statistics_web_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Mediahouse Statistics Web Server Detect
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
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

include("revisions-lib.inc");
tag_summary = "We detected the remote web server as a 
Mediahouse Statistics web server. This web server suffers from a security 
vulnerability that enables attackers to gain sensitive information on the 
current logged events on the public web server (the server being monitored 
by MediaHouse).
This information includes: who is on (currently surfing users), the user's 
actions, customer's IP addresses, referrer URLs, hidden directories, web 
server usernames and passwords, and more.

Some versions of the product also suffer from a flaw that allows attackers 
to overflow an internal buffer causing it to execute arbitrary code.";

tag_solution = "Block the web server's port number on your Firewall, and
upgrade to the latest version if necessary.";

# Could also cover BugtraqID:734, CVE:CVE-1999-0931

if(description)
{
 script_id(10748);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1568);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2000-0776");

 name = "Mediahouse Statistics Web Server Detect";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Mediahouse Statistics Web Server Detection";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_keys("www/statistics-server");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

buf  = get_http_banner(port:port);

if (egrep(pattern:"^Server: Statistics Server", string:buf))
{
 buf = strstr(buf, "Location: ");
 buf = buf - "Location: ";
 subbuf = strstr(buf, string("\n"));
 buf = buf - subbuf;
 buf = buf - raw_string(0x0D);
 soc = http_open_socket(port);
 if (soc)
 {
  req = http_get(item:buf, port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);
  http_close_socket(soc);

  if ("Statistics Server " >< buf)
  {
   buf = strstr(buf, "<TITLE>Statistics Server ");
   buf = buf - "<TITLE>Statistics Server ";
   subbuf = strstr(buf, "</TITLE>");
   buf = buf - subbuf;
   buf = buf - "</TITLE>";
   version = buf;

   buf = "Remote host is running Statistics Server version: ";
   buf = buf + version;
   if(ereg(pattern:"(([0-4]\.[0-9].*)|5\.0[0-2])", string:version))
   {
    # should be a separate plugin ?
    report = string("According to its version number, the remote MediaHouse\n",
        	      "Statistics Server is vulnerable to a buffer overflow that\n",
		      "allows anyone to execute arbitrary code as root.\n\n",
		      "Solution: Upgrade to version 5.03 or newer");
   security_hole(data:report, port:port);
   }
   else
   {
    security_hole(port);
   }
  }
 }
}


