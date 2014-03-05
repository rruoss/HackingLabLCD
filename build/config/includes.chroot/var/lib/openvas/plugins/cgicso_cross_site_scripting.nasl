# OpenVAS Vulnerability Test
# $Id: cgicso_cross_site_scripting.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CGIEmail's Cross Site Scripting Vulnerability (cgicso)
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2001 SecurITeam
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
tag_summary = "The remote web server contains a CGI which is vulnerable to a cross site
scripting vulnerability.

Description :

The remote web server contains the 'CGIEmail' CGI, a web based form to
send emails.

The remote version of this software contains a vulnerability caused by 
inadequate processing of queries by CGIEmail's cgicso  that results in a 
cross site scripting condition.";

tag_solution = "Modify cgilib.c to contain a stripper function that will remove any HTML 
or JavaScript tags.";

if (description)
{
 script_id(10780);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("CGIEmail's Cross Site Scripting Vulnerability (cgicso)");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if a remote host is vulnerable to the cgicso vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2001 SecurITeam");
 script_dependencies("find_service.nasl", "http_version.nasl","cross_site_scripting.nasl");
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

if(!get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if ( get_kb_item("www/no404/" + port )) exit(0);



check = string("<script>vulnerable</script>");


foreach d (cgi_dirs())
{
 url = string(d, "/cgicso");
 data = string(url, "?query=<script>alert('foo')</script>");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(!ereg(pattern:"<script>alert('foo')</script>", string:buf))exit(0);

 if (check >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}
