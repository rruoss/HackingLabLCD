# OpenVAS Vulnerability Test
# $Id: worldclient_server_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WorldClient for MDaemon Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Currently no testing scripts for WorldClient vulnerabilities.  Added
# notes of the current list of WorldClient vulnerabilities
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
tag_summary = "We detected the remote web server is 
running WorldClient for MDaemon. This web server enables attackers 
with the proper username and password combination to access locally 
stored mailboxes.

In addition, earlier versions of WorldClient suffer from buffer overflow 
vulnerabilities, and web traversal problems (if those are found the Risk 
factor is higher).";

tag_solution = "Make sure all usernames and passwords are adequately long and
that only authorized networks have access to this web server's port number 
(block the web server's port number on your firewall).

For more information see:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient";


if(description)
{
 script_id(10745); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2000-0660");
 script_bugtraq_id(1462, 2478, 4687, 4689, 823);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "WorldClient for MDaemon Server Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Check for WorldClient for MDaemon";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 3000);
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
 include("misc_func.inc");
 
 ports = add_port_in_list(list:get_kb_list("Services/www"), port:3000);
 foreach port (ports)
 {
 banner = get_http_banner(port:port);
 if(banner)
 {

  #display(buf);
  if (egrep(pattern:"^Server: WDaemon/", string:banner))
  {
   security_note(port);
   buf = strstr(banner, "WDaemon/");
   buf = banner - "WDaemon/";
   subbuf = strstr(buf, string("\r\n"));
   buf = buf - subbuf;
   version = buf;

   buf = "Remote WorldClient server version is: ";
   buf = buf + version;
   if (version < "4")
   {
    # I'm wondering if this should not be in another plugin (rd) 
    report = string("\nThis version of WorldClient contains serious security vulnerabilities.\n",
    "It is advisable that you upgrade to the latest version\n",
    "Solution : Upgrade\n");
    security_hole(data:report, port:port);
    }
   }
  }
 }
