###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_bbcode_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpMyAdmin 'error.php' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to inject arbitrary HTML code
  within the error page and conduct phishing attacks.
  Impact Level: Application";
tag_affected = "phpMyAdmin version 3.3.8.1 and prior.";
tag_insight = "The flaw is caused by input validation errors in the 'error.php' script when
  processing crafted BBcode tags containing '@' characters, which could allow
  attackers to inject arbitrary HTML code within the error page and conduct
  phishing attacks.";
tag_solution = "No solution or patch is available as of 10th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phpmyadmin.net/home_page/downloads.php";
tag_summary = "The host is running phpMyAdmin and is prone to Cross-Site Scripting
  Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801660";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4480");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("phpMyAdmin 'error.php' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15699/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3133");

  script_description(desc);
  script_summary("Check if phpMyAdmin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
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

## Get phpMyAdmin Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get phpMyAdmin Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
url = string(dir,"/error.php?type=OpenVAS+XSS+Test&error=Attack+via+",
                 "characters+injection+-+[a%40http://www.openvas.org%40_self]",
                 "This%20Is%20a%20Link[%2Fa]");

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:'<h1>phpMyAdmin - OpenVAS XSS Test</h1>',
                   extra_check: make_list('Attack via characters injection',
                   '<a href="http://www.openvas.org" target="_self">This Is a Link</a>')))
{
  security_warning(port);
  exit(0);
}
