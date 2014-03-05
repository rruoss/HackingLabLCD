# OpenVAS Vulnerability Test
# $Id: ldu_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Land Down Under <= 800 Multiple Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat doti cc>
# Changes by Tenable Network Security :
# - improved description
# - do a more reliable test (if magic_quotes is on the host is not vulnerable)
# - added references
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
tag_summary = "The remote web server contains a PHP script that permits SQL injection
and cross-site scripting attacks. 

Description :

The remote version of Land Down Under is prone to various SQL
injection and cross-site scripting attacks provided PHP's
'magic_quotes' setting is disabled due to its failure to sanitize the
request URI before using it in 'system/functions.php' in the function
'ldu_log()'.  A malicious user may be able to exploit this issue to
manipulate SQL queries, steal authentication cookies, and the like. 

In addition, it also fails to properly sanitize the user-supplied
signature in forum posts..  A malicious user can exploit this
vulnerability to steal authentication cookies and manipulate the HTML
format in 'forums.php'.";

tag_solution = "Upgrade to Land Down Under version 801 or later.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(19678);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2674", "CVE-2005-2675", "CVE-2005-2780");
 script_bugtraq_id(14618, 14619, 14677);
 script_xref(name:"OSVDB", value:"19298");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "Land Down Under <= 800 Multiple Vulnerabilities";
 script_name(name);

 script_description(desc);

 summary = "Checks for SQL injection in LDU's index.php";

 script_summary(summary);

 script_category(ACT_ATTACK);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencies("ldu_detection.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.org/archive/1/408664");
 script_xref(name : "URL" , value : "http://www.neocrome.net/forums.php?m=posts&amp;p=83412#83412");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2005-08/0395.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 dir = matches[2];

 req = http_get(
   item:string(
     dir, "/index.php?",
     "m='", SCRIPT_NAME
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if 
 ( 
   egrep(string:res, pattern:string("MySQL error.+syntax to use near '", SCRIPT_NAME))
 )
 {
        security_hole(port);
        exit(0);
 }

 # Check the version number in case magic_quotes is enabled.
 if (ver =~ "^([0-7]|800)") {
      desc = str_replace(
        string:desc,
        find:"See also :",
        replace:string(
          "***** OpenVAS has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of Land Down\n",
          "***** Under installed there.\n",
          "\n",
          "See also :"
        )
      );
      security_hole(port:port, data:desc);
      exit(0);
 }
}
