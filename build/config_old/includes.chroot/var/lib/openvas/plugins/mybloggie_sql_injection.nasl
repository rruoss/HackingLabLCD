# OpenVAS Vulnerability Test
# $Id: mybloggie_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: myBloggie Multiple Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "The remote host is running myBloggie, a web log system written in PHP.

The remote version of this software has been found contain multiple 
vulnerabilities:

 * Full Path Disclosure
 Due to an improper sanitization of the post_id parameter, it's possible
 to show the full path by sending a simple request.

 * Cross-Site Scripting (XSS)
 Input passed to 'year' parameter in viewmode.php is not properly sanitised
 before being returned to users. This can be exploited execute arbitrary 
 HTML and script code in a user's browser session in context of a vulnerable 
 site.

 * SQL Injection
 When myBloggie get the value of the 'keyword' parameter and put it in the
 SQL query, don't sanitise it. So a remote user can do SQL injection attacks.";

tag_solution = "Patches have been provided by the vendor and are available at:
http://mywebland.com/forums/viewtopic.php?t=180";

# Multiple vulnerabilities in myBloggie 2.1.1
# "Alberto Trivero" <trivero@jumpy.it>
# 2005-05-05 17:46

if(description)
{
 script_id(18209);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1140", "CVE-2005-1498", "CVE-2005-1499", "CVE-2005-1500");
 script_bugtraq_id(13192, 13507);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "myBloggie Multiple Vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for the presence of a myBloggie";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
function check(loc)
{
 req = http_get(item:string(loc, "/index.php?mode=viewid&post_id=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
 if( r == NULL )exit(0);
 if("You have an error in your SQL syntax" >< r)
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

