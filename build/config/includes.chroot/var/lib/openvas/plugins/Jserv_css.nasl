# OpenVAS Vulnerability Test
# $Id: Jserv_css.nasl 17 2013-10-27 14:01:43Z jan $
# Description: JServ Cross Site Scripting
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
tag_summary = "The remote web server is vulnerable to a cross-site scripting issue.

Description :

Older versions of JServ (including the version shipped with Oracle9i App 
Server v1.0.2) are vulnerable to a cross site scripting attack using a 
request for a non-existent .JSP file.";

tag_solution = "Upgrade to the latest version of JServ available at http://java.apache.org. 
Also consider switching from JServ to TomCat, since JServ is no longer 
maintained.";

if(description)
{
 script_id(10957);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "JServ Cross Site Scripting";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Tests for JServ Cross Site Scripting";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss")))exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/a.jsp/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< res) security_warning(port);
}
