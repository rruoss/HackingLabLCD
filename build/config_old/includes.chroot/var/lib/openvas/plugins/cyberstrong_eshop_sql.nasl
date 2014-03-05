# OpenVAS Vulnerability Test
# $Id: cyberstrong_eshop_sql.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cyberstrong eShop SQL Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
# Fixed by Tenable: - added See also.
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
tag_summary = "The remote host is running Cyberstrong eShop, a shopping cart written
in ASP.

The remote version of this software contains several input validation
flaws leading to SQL injection vulnerabilities.  An attacker may
exploit these flaws to affect database queries, possibly resulting in
disclosure of sensitive information (for example, the admin's user and
password) and attacks against the underlying database.";

tag_solution = "None at this time";

if(description)
{
 script_id(19391);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2003-0509");
 script_bugtraq_id(14101, 14103, 14112);
 script_xref(name:"OSVDB", value:"10098");
 script_xref(name:"OSVDB", value:"10099");
 script_xref(name:"OSVDB", value:"10100");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 name = "Cyberstrong eShop SQL Injection Vulnerabilities";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks for an SQL injection in Cyberstrong eShop v4.2";

 script_summary(summary);

 script_category(ACT_ATTACK);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2003-07/0006.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port)) exit(0);

function check(url)
{
 req = http_get(item:url +"/20Review.asp?ProductCode='", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( 'Microsoft OLE DB Provider for ODBC Drivers' >< res && 'ORDER BY TypeID' >< res )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
