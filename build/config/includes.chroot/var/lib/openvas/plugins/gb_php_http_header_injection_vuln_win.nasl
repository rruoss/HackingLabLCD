###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_http_header_injection_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP 'main/SAPI.c' HTTP Header Injection Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allows remote attackers to insert arbitrary
  headers, conduct cross-site request-forgery, cross-site scripting,
  HTML-injection, and other attacks.
  Impact Level: Application";
tag_affected = "PHP version prior to 5.3.11
  PHP version 5.4.x through 5.4.0RC2";
tag_insight = "The sapi_header_op function in main/SAPI.c in PHP does not properly determine
  a pointer during checks for %0D sequences.";
tag_solution = "Upgrade to PHP 5.4.1 RC1 or later
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to HTTP header injection
  vulnerability.";

if(description)
{
  script_id(802966);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4388", "CVE-2011-1398");
  script_bugtraq_id(55527, 55297);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-24 18:58:41 +0530 (Mon, 24 Sep 2012)");
  script_name("PHP 'main/SAPI.c' HTTP Header Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/09/02/1");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/09/07/3");
  script_xref(name : "URL" , value : "http://article.gmane.org/gmane.comp.php.devel/70584");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/09/05/15");
  script_xref(name : "URL" , value : "http://security-tracker.debian.org/tracker/CVE-2012-4388");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_php_detect_win.nasl");
  script_require_keys("PHP/Ver/win");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
phpVer = "";

## Get the version
phpVer = get_kb_item("PHP/Ver/win");
if(!phpVer){
  exit(0);
}

## To check PHP version
if(version_is_less(version:phpVer, test_version:"5.3.11") ||
   version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.0.rc2")){
  security_warning(0);
}
