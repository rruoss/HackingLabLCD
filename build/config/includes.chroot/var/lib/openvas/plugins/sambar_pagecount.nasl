# OpenVAS Vulnerability Test
# $Id: sambar_pagecount.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar webserver pagecount hole
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
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
tag_summary = "By default, there is a pagecount script with Sambar Web Server
located at http://sambarserver/session/pagecount
This counter writes its temporary files in c:\sambardirectory\tmp.
It allows to overwrite any files on the filesystem since the 'page'
parameter is not checked against '../../' attacks.

Reference : http://www.securityfocus.com/archive/1/199410";

tag_solution = "Remove this script";

if(description)
{
 script_id(10711);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3091, 3092);
 script_cve_id("CVE-2001-1010");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Sambar webserver pagecount hole";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Make a request like http://www.example.com/session/pagecount";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 Vincent Renardias");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
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

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:"/session/pagecount", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  if( ("Server: SAMBAR" >< data) && !ereg(string:data, pattern:"^404"))
  {
   security_warning(port);
  }
 }
}
