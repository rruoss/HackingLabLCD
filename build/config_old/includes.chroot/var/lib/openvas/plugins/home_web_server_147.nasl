###############################################################################
# OpenVAS Vulnerability Test
# $Id: home_web_server_147.nasl 15 2013-10-27 12:49:54Z jan $
#
# Home Web Server Graphical User Interface Remote Denial Of Service Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "According to its version number, the remote version of the Home Web Server is
  prone to a denial-of-service vulnerability because it fails to adequately
  handle malformed HTTP requests.

  Attackers can exploit this issue to cause the graphical interface of
  the server to stop responding, denying service to the administrator.

  Home Web Server 1.7.1.147 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100163);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
 script_bugtraq_id(34698);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Home Web Server Graphical User Interface Remote Denial Of Service Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Home Web Server is vulnerable to DoS");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34698");
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(get_kb_item("Services/www/" + port + "/embedded" ))exit(0);

banner = get_http_banner(port:port);
if (!banner)exit(0);
if(!egrep(pattern:"Server: .*\(HWS[0-9]+\)", string:banner) ) exit(0);

version = eregmatch(pattern: "HWS([0-9]+)", string: banner);

if(version[1] == "147") {

 security_warning(port:port);
 exit(0);

}  

exit(0);
