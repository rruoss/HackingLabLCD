# OpenVAS Vulnerability Test
# $Id: translate_f.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ASP/ASA source using Microsoft Translate f: bug
#
# Authors:
# Alexander Strouk
#
# Copyright:
# Copyright (C) 2000 Alexander Strouk
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
tag_summary = "There is a serious vulnerability in Windows 2000 (unpatched by SP1) that 
allows an attacker to view ASP/ASA source code instead of a processed file.

ASP source code can contain sensitive information such as username's and 
passwords for ODBC connections.";

tag_solution = "install all the latest Microsoft Security Patches (Note: This
vulnerability is eliminated by installing Windows 2000 Service Pack 1)";

if(description)
{
 script_id(10491); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1578);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-0778");
 name = "ASP/ASA source using Microsoft Translate f: bug";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "downloads the source of IIS scripts such as ASA,ASP";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 copyright="This script is Copyright (C) 2000 Alexander Strouk";
 script_copyright(copyright);
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
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
if  (! port || get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("GET /global.asa\\ HTTP/1.0\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Translate: f\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv_headers2(socket:soc);
  if( r == NULL ) exit(0);
  if("Content-Type: application/octet-stream" >< r)security_warning(port);
  close(soc);
 }
}

