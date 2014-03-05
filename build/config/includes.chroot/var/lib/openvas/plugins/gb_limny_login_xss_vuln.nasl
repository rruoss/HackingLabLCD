###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_login_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Limny 'login.php' Script Cross Site Scripting Vulnerability
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
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Limny version 3.0.1";
tag_insight = "Input passed via the URL to 'admin/login.php' is not properly sanitised
  before being returned to the user.";
tag_solution = "Upgrade to Limny version 3.0.2 or later
  For updates refer to http://www.limny.org/download";
tag_summary = "This host is running Limny and is prone to cross site scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802983";
CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5343");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-12 14:16:51 +0530 (Fri, 12 Oct 2012)");
  script_name("Limny 'login.php' Script Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/78093");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47444");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72113");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012010034");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/codes/limny_xss.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5066.php");

  script_description(desc);
  script_summary("Check for XSS vulnerability in Limny");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("limny/installed");
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

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Limny Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct xss attack
url = dir + '/admin/login.php/"><script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"><script>alert\(document.cookie\)<",
                   extra_check:">Limny<")){
  security_warning(port:port);
}
