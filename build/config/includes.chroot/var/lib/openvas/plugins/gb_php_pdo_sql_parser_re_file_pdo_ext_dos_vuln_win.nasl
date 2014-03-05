###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_pdo_sql_parser_re_file_pdo_ext_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP pdo_sql_parser.re 'PDO' extension DoS vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service condition.
  Impact Level: Application";
tag_affected = "PHP version before 5.3.14 and 5.4.x before 5.4.4 on Windows";
tag_insight = "The flaw is due to an error in the PDO extension in pdo_sql_parser.re
  file, which fails to determine the end of the query string during parsing of
  prepared statements.";
tag_solution = "Upgrade to PHP Version 5.3.14 or 5.4.4 or later,
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone denial of service
  vulnerability.";

if(description)
{
  script_id(802670);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3450");
  script_bugtraq_id(54777);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-27 17:03:25 +0530 (Mon, 27 Aug 2012)");
  script_name("PHP pdo_sql_parser.re 'PDO' extension DoS vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Jun/60");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=61755");
  script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=769785");

  script_description(desc);
  script_summary("Check for the version of PHP on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

## Variable Initialisation
phpVer = "";

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(phpVer)
{
  ##Check for PHP version < 5.3.14 and 5.4.x before 5.4.4
  if(version_is_less(version:phpVer, test_version:"5.3.14") ||
     version_in_range(version: phpVer, test_version: "5.4.0", test_version2: "5.4.3")){
    security_warning(0);
  }
}
