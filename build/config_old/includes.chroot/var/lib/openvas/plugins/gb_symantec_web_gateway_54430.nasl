###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_54430.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec Web Gateway Password Change Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Symantec Web Gateway is prone to a security-bypass vulnerability.

Successful exploits may allow attackers to change another user's
password allowing them to gain unauthorized access in the context of
the affected user. This may aid in further attacks.

Symantec Web Gateway versions 5.0.x.x are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103547";
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54430);
 script_cve_id("CVE-2012-2977");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 12 $");

 script_name("Symantec Web Gateway Password Change Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54430");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/web-gateway");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-22 10:26:36 +0200 (Wed, 22 Aug 2012)");
 script_description(desc);
 script_summary("Determine if Symantec Web Gateway is prone to a security-bypass vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_web_gateway_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("symantec_web_gateway/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
pass  = "A,3$" + rand();
pass1 = "B,4$" + rand();
host = get_host_name();

ex = "USERNAME=admin&password2=" + pass  + "&password=" + pass1  + "&Save=Save&target=executive_summary.php";
len = strlen(ex);

req = string("POST /spywall/temppassword.php HTTP/1.1\r\n",
             "Accept-Encoding: identity\r\n",
             "Content-Length: ",len,"\r\n",
             "Host: ",host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Connection: close\r\n",
             "\r\n",
             ex);

data = http_send_recv(data:req,port:port);

if("You have logged in using a temporary password" >< data && "Please select a new one" >< data && "Password doesn't match the retyped password" >< data) {
  
  security_warning(port:port);
  exit(0);

}
