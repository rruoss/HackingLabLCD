# OpenVAS Vulnerability Test
# $Id: compaq_wbem_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: Compaq WBEM Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
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
tag_summary = "We detected the remote web server to be a Compaq WBEM server. 
This web server enables attackers to gather sensitive information on 
the remote host, especially if anonymous access has been enabled.

Sensitive information includes: Platform name and version (including 
service packs), installed hotfixes, Running services, installed Drivers, 
boot.ini content, registry settings, NetBIOS name, system root directory, 
administrator full name, CPU type, CPU speed, ROM versions and revisions, 
memory size, sever recovery settings, and more.";

tag_solution = "Disable the Anonymous access to Compaq WBEM web server, or
block the web server's port number on your Firewall.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(10746);
 script_version("$Revision: 57 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");

 name = "Compaq WBEM Server Detection";
 script_name(name);

 
 script_description(desc);

 summary = "Compaq WBEM Server Detect";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 2301);
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
 
 ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
 foreach port (ports)
 {
 banner = get_http_banner(port:port);
 if(banner)
 {
  buf = banner;
  if (egrep(pattern:"^Server: CompaqHTTPServer/", string:buf))
  {
   mod_buf = strstr(buf, "Server: CompaqHTTPServer/");
   mod_buf = mod_buf - "Server: CompaqHTTPServer/";
   subbuf = strstr(mod_buf, string("\n"));
   mod_buf = mod_buf - subbuf;
   version = mod_buf;

   wbem_version = "false";
   if (buf >< "var VersionCheck = ")
   {
    mod_buf = strstr(buf, "var VersionCheck = ");
    mod_buf = mod_buf - string("var VersionCheck = ");
    mod_buf = mod_buf - raw_string(0x22);
    subbuf = strstr(mod_buf, raw_string(0x22));
    mod_buf = mod_buf - subbuf;
    wbem_version = mod_buf;
   }

   buf = "Remote Compaq HTTP server version is: ";
   buf = buf + version;
   if (!(wbem_version == "false"))
   {
    buf = string(buf, "\nCompaq WBEM server version: ");
    buf = buf + wbem_version;
   }
   report = string(desc, "\n", buf);
   security_warning(data:buf, port:port);
  }
  }
 }
