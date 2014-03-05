# OpenVAS Vulnerability Test
# $Id: cobalt_overflow_cgi.nasl 16 2013-10-27 13:09:52Z jan $
# Description: overflow.cgi detection
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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
tag_summary = "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.
Some versions of this CGI allow remote users to execute arbitrary commands
with the privileges of the web server.

*** OpenVAS just checked the presence of this file 
*** but did not try to exploit the flaw, so this might
*** be a false positive
   
See: http://www.cert.org/advisories/CA-2002-35.html";

tag_solution = "get a newer software from Cobalt";

if(description)
{
 script_id(80051);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "overflow.cgi detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for the presence of a CGI";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_hole(port);
