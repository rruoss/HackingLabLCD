##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_safe_search_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "WordPress Safe Search Plugin 0.7 and prior";
tag_insight = "The input passed to 'v1' parameter in
  'wp-content/plugins/wp-safe-search/wp-safe-search-jx.php' script is not
  properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 16th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/";
tag_summary = "This host is running WordPress and is prone to Cross Site Scripting
  Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801490";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-4518");
  script_bugtraq_id(45267);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42544");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/WordPress.Safe.Search.0.7.Reflected.Cross-site.Scripting/66");

  script_description(desc);
  script_summary("Check the exploit string on WordPress Safe Search Plugin");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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


## Get HTTP Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

## Get WordPress Path from KB
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

if(dir != NULL)
{
  # Try expliot and check response
  sndReq = http_get(item:string(dir, "/wp-content/plugins/wp-safe-search/" +
                      "wp-safe-search-jx.php?v1=<script>alert(XSS-Testing)</script>"), port:wpPort);
  rcvRes = http_send_recv(port:wpPort, data:sndReq);
  if("<script>alert(XSS-Testing)</script>" >< rcvRes){
    security_warning(wpPort);
  }
}
