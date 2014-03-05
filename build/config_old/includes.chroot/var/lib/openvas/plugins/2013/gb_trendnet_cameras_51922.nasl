###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_cameras_51922.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple Trendnet Camera Products Remote Security Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103791";

tag_insight = "On vulnerable devices it is possible to access the livestream 
without any authentication by requesting http://<ip-of camera>/anony/mjpg.cgi.";

tag_impact = "Successfully exploiting this issue will allow remote attackers to gain
access to a live stream from the camera.";

tag_affected = "Trendnet TV-VS1P V1.0R 0
Trendnet TV-VS1 1.0R 0
Trendnet TV-IP422WN V1.0R 0
Trendnet TV-IP422W A1.0R 0
Trendnet TV-IP422 A1.0R 0
Trendnet TV-IP410WN 1.0R 0
Trendnet TV-IP410W A1.0R 0
Trendnet TV-IP410 A1.0R 0
Trendnet TV-IP322P 1.0R 0
Trendnet TV-IP312WN 1.0R 0
Trendnet TV-IP312W A1.0R 0
Trendnet TV-IP312 A1.0R 0
Trendnet TV-IP252P B1.xR 0
Trendnet TV-IP212W A1.0R 0
Trendnet TV-IP212 A1.0R 0
Trendnet TV-IP121WN v2.0R 0
Trendnet TV-IP121WN 1.0R 0
Trendnet TV-IP121W A1.0R 0
Trendnet TV-IP110WN 2.0R 0
Trendnet TV-IP110WN 1.0R
Trendnet TV-IP110W A1.0R 0
Trendnet TV-IP110 A1.0R 0";

tag_summary = "Multiple Trendnet Camera products are prone to a remote security-
bypass vulnerability.";

tag_solution = "Vendor updates are available.";
tag_vuldetect = "Test if it is possible to access /anony/mjpg.cgi without authentication";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(51922);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_name("Multiple Trendnet Camera Products Remote Security Bypass Vulnerability");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51922");
 script_xref(name:"URL", value:"http://www.trendnet.com/press/view.asp?id=1959");
 script_xref(name:"URL", value:"http://www.trendnet.com/products/proddetail.asp?prod=145_TV-IP110W");
 script_xref(name:"URL", value:"http://console-cowboys.blogspot.com.au/2012/01/trendnet-cameras-i-always-feel-like.html");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-19 18:42:42 +0200 (Thu, 19 Sep 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to access /anony/mjpg.cgi");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("401 Unauthorized" >!< banner || 'Basic realm="netcam"' >!< banner)exit(0);

req = 'GET /anony/mjpg.cgi HTTP/1.0\r\n\r\n';
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 200 OK" && "x-mixed-replace" >< buf && "image/jpeg" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(99);

