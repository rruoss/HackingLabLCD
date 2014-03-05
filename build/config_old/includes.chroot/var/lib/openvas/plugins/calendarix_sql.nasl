# OpenVAS Vulnerability Test
# $Id: calendarix_sql.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Calendarix SQL Injection Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
# Fixed by Tenable:
#  - added CVE xref.
#  - added BID 13825,
#  - added OSVDB xrefs.
#  - added link to original advisory.
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
tag_summary = "The remote host is running Calendarix, a PHP-based calendar system.

The remote version of this software is prone to a remote file include
vulnerability as well as multiple cross-site scripting, and SQL
injection vulnerabilities.  Successful exploitation could result in
execution of arbitrary PHP code on the remote site, a compromise of the
application, disclosure or modification of data, or may permit an
attacker to exploit vulnerabilities in the underlying database
implementation.";

tag_solution = "None at this time.";

if(description)
{
 script_id(18410);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_cve_id("CVE-2005-1865");
 script_bugtraq_id(13825, 13826);
 script_xref(name:"OSVDB", value:"16971");
 script_xref(name:"OSVDB", value:"16972");
 script_xref(name:"OSVDB", value:"16973");
 script_xref(name:"OSVDB", value:"16974");
 script_xref(name:"OSVDB", value:"16975");

 name = "Calendarix SQL Injection Vulnerability";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for multiple vulnerabilities in Calendarix";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.swp-scene.org/?q=node/62");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
 req = http_get(item:string(url, "/cal_week.php?op=week&catview=999'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if ( 'mysql_num_rows(): supplied argument is not a valid MySQL result' >< r )
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
