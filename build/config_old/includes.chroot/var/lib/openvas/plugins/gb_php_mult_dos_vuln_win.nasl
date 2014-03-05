###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP Multiple Denial of Service Vulnerabilities (Windows)
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
tag_impact = "Successful exploitation could allow remote attackers to cause denial of
  service conditions.
  Impact Level: Application";
tag_affected = "PHP Version 5.3.8 on windows.";
tag_insight = "Multiple flaws are due to
  - An error in application which makes calls to the 'zend_strndup()' function
    without checking the returned values. A local user can run specially
    crafted PHP code to trigger a null pointer dereference in zend_strndup()
    and cause the target service to crash.
  - An error in 'tidy_diagnose' function, which might allows remote attackers
    to cause a denial of service via crafted input.";
tag_solution = "No solution or patch is available as of 23rd January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to multiple denial of
  service vulnerabilities.";

if(description)
{
  script_id(802566);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-4153", "CVE-2012-0781");
  script_bugtraq_id(51417);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-23 11:30:34 +0530 (Mon, 23 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP Multiple Denial of Service Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://cxsecurity.com/research/103");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026524");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18370/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-01/0092.html");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");
if(phpVer != NULL)
{
  ##Check for PHP version
  if(version_is_equal(version:phpVer, test_version:"5.3.8")){
    security_warning(0);
  }
}
