# OpenVAS Vulnerability Test
# $Id: ows_bin_cgi.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ows-bin
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- script id
#	- minor changes in the english description
#
# Copyright:
# Copyright (C) 2000 Noam Rathaus
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
tag_summary = "Oracle's Web Listener (a component of the Oracle Application Server),
is installed and can be used by a remote attacker to run arbitrary 
commands on the web server.

Read more about this hole at:
http://www.securiteam.com/windowsntfocus/Oracle_Web_Listener_4_0_x_CGI_vulnerability.html";

tag_solution = "If 'ows-bin' is the default CGI directory used by the Oracle Application Server Manager,
then remove the ows-bin virtual directory or point it to a more benign directory.
If 'ows-bin' is not the default then verify that there are no batch files in this directory.";

if(description)
{
 script_id(10348);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1053);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 script_cve_id("CVE-2000-0169");
 name = "ows-bin";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks if ows-bin is vulnerable";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
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
include("http_keepalive.inc");
port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/ows-bin/perlidlc.bat", port:port);
if(res)
{
  req = http_get(item:"/ows-bin/perlidlc.bat?&dir", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   http_close_socket(soc);
   if("ows-bin:" >< result)security_hole(port);
  }
}

