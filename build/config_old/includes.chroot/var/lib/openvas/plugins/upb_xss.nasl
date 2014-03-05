# OpenVAS Vulnerability Test
# $Id: upb_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Ultimate PHP Board multiple XSS flaws
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat dot cc>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is affected by several cross-site
scripting vulnerabilities.  These issues are due to a failure of the
application to properly sanitize user-supplied input.";

tag_solution = "Install vendor patch";

if(description)
{
 script_id(19498);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2004");
 script_bugtraq_id(13971);
 script_xref(name:"OSVDB", value:"17362");
 script_xref(name:"OSVDB", value:"17363");
 script_xref(name:"OSVDB", value:"17364");
 script_xref(name:"OSVDB", value:"17365");
 script_xref(name:"OSVDB", value:"17366");
 script_xref(name:"OSVDB", value:"17367");
 script_xref(name:"OSVDB", value:"17368");
 script_xref(name:"OSVDB", value:"17369");
 script_xref(name:"OSVDB", value:"17370");
 script_xref(name:"OSVDB", value:"17371");
 script_xref(name:"OSVDB", value:"17372");
 script_xref(name:"OSVDB", value:"17373");
 script_xref(name:"OSVDB", value:"17374");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Ultimate PHP Board multiple XSS flaws";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks for XSS in login.php";

 script_summary(summary);

 script_category(ACT_ATTACK);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.myupb.com/forum/viewtopic.php?id=26&amp;t_id=118");
 script_xref(name : "URL" , value : "http://securityfocus.com/archive/1/402461");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "'><script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?ref=",
     exss
   ), 
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_warning(port);
        exit(0);
 }
}
