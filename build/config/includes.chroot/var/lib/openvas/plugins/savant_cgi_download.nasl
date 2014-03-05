# OpenVAS Vulnerability Test
# $Id: savant_cgi_download.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Savant original form CGI access
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
tag_summary = "A security vulnerability in the Savant web server allows attackers to download the original form of CGIs (unprocessed).
This would allow them to see any sensitive information stored inside those CGIs.";

tag_solution = "The newest version is still vulnerable to attack (version 2.1), it would be recommended that users cease to use this product.

Additional information:
http://www.securiteam.com/exploits/Savant_Webserver_exposes_CGI_script_source.html";


if (description)
{
 script_id(10623);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1313);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-0521");
 script_name("Savant original form CGI access");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("Determine if a remote host is Savant web server, and whether it is vulnerable to attack"); script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 if ("Server: Savant/">< banner)
 {
  foreach dir (cgi_dirs())
  {
  if (is_cgi_installed_ka(port:port, item:string(dir, "/cgitest.exe")))
  {
   data = http_get(item:string(dir, "/cgitest.exe"), port:port);

   soctcp80 = http_open_socket(port);
   resultsend = send(socket:soctcp80, data:data);
   resultrecv = http_recv(socket:soctcp80);
   http_close_socket(soctcp80);
   if ((resultrecv[0] == string("M")) && (resultrecv[1] == string("Z"))) {
   security_hole(port:port);}
  }
  else
  {
   security_warning(port:port);
  }
  }
 }
}
