###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wp_stats_dashboard_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress WP-Stats-Dashboard Plugin Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "WordPress WP-Stats-Dashboard version 2.6.6.1 and prior.";
tag_insight = "The flaws are due to input passed via,
  - 'icon', 'url', 'name', 'type', 'code', 'username' GET parameters to
    '/wp-content/plugins/wp-stats-dashboard/view/admin/admin_profile_type.php'
  - 'onchange' GET parameter to
    '/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/select-trend.php'
  - and 'submenu' GET parameter to
    '/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/submenu.php'
  is not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 19th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/wp-stats-dashboard/download/";
tag_summary = "This host is installed with WordPress WP-Stats-Dashboard Plugin and
  is prone to multiple cross-site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902713";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-23 07:05:00 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress WP-Stats-Dashboard Plugin Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Aug/128");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519348");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/multiple_xss_in_wp_stats_dashboard.html");

  script_description(desc);
  script_summary("Check if WordPress WP-Stats-Dashboard plugin is vulnerable XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Path of Vulnerable Page
url = dir + "/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/" +
      "select-trend.php?onchange=><script>alert(document.cookie);</script>";

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document." +
                                               "cookie\);</script>")){
  security_warning(port);
}