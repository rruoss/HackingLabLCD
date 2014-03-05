###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_wptouch_path_disc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress WPtouch Plugin Path Disclosure Vulnerability
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
tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803849";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-06 11:43:33 +0530 (Tue, 06 Aug 2013)");
  script_name("WordPress WPtouch Plugin Path Disclosure Vulnerability");

  tag_summary =
"This host is installed with WordPress WPtouch plugin and is prone to path
disclosure vulnerability.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to disclose the path
or not.";

  tag_insight =
"Flaws is due to error in the php files in plugin folder and subfolders.";

  tag_impact =
"Successful exploitation will allow attacker to gain sensitive information
like installation path.";

  tag_affected =
"WPtouch version 1.9.7.1 and prior";

  tag_solution =
"No solution or patch is available as of 09th August, 2013. Information
regarding this issue will be updated once the solution details are available.
For Updated refer to http://wordpress.org/plugins/wptouch";

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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/21071");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080037");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122687");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wptouch-wptouch-pro-xss-path-disclosure");
  script_summary("Check if WordPress WPtouch plugin is prone to path disclosure vulnerability");
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
port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct the Attack Request
url = dir + "/wp-content/plugins/wptouch/wptouch.php";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
   pattern:"<b>Fatal error</b>: .*load_plugin_textdomain\(\) in.*wptouch.php"))
{
  security_warning(port);
  exit(0);
}
