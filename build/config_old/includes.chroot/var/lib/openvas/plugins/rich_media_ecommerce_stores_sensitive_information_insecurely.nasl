# OpenVAS Vulnerability Test
# $Id: rich_media_ecommerce_stores_sensitive_information_insecurely.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Rich Media E-Commerce Stores Sensitive Information Insecurely
#
# Authors:
# SecurITeam
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
tag_summary = "A security vulnerability in Rich Media's JustAddCommerce  allows attackers 
to gain sensitive client information by accessing a log file that is stored 
in an insecure manner";

tag_solution = "contact the vendor for a patch
";
if(description)
{
 script_id(10874);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4172);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Rich Media E-Commerce Stores Sensitive Information Insecurely";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Rich Media E-Commerce Stores Sensitive Information Insecurely";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SecurITeam");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securiteam.com/windowsntfocus/5XP0N0A6AU.html");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

# Check starts here

function check(req)
{
  req = http_get(item:req, port:port); 
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  if (("HttpPost Retry" >< buf) && ("checkouthtml" >< buf) && ("password" >< buf))
  {
   	security_warning(port:port);
	exit(0);
  }
 return(0);
}

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


check(req:"/rtm.log");
foreach dir (cgi_dirs())
{
check(req:string(dir, "/rtm.log"));
}
