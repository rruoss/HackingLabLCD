# OpenVAS Vulnerability Test
# $Id: calendar_express_flaws.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Calendar Express Multiple Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server contains a PHP script which is vulnerable to a cross
site scripting and SQL injection vulnerability.

Description :

The remote host is using Calendar Express, a PHP web calendar.

A vulnerability exists in this version which may allow an attacker to 
execute arbitrary HTML and script code in the context of the user's browser, 
and SQL injection.

An attacker may exploit these flaws to use the remote host to perform attacks
against third-party users, or to execute arbitrary SQL statements on the remote
SQL database.";

tag_solution = "Upgrade to the latest version of this software.";

#  Ref: aLMaSTeR HacKeR

if(description)
{
 script_id(19749);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2007-3627");
 script_bugtraq_id(14504, 14505);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Calendar Express Multiple Flaws";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks Calendar Express XSS and SQL flaws";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
include("global_settings.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") )
 {
   	security_hole(port);
   exit(0);
 }
}

if (thorough_tests) dirs = make_list("/calendarexpress", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
