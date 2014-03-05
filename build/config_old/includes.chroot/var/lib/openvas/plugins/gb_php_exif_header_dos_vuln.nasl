###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_exif_header_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP EXIF Header Denial of Service Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  obtain sensitive information or cause a denial of service.
  Impact Level: Application";
tag_affected = "PHP version 5.4.0 beta 2 on windows.";
tag_insight = "The flaw is due to an integer overflow error in 'exif_process_IFD_TAG'
  function in the 'ext/exif/exif.c' file, Allows remote attackers to cause
  denial of service via crafted offset_val value in an EXIF header.";
tag_solution = "Upgrade to PHP version 5.4.0 beta 4 or later.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(802349);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4566");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-01 11:41:26 +0530 (Thu, 01 Dec 2011)");
  script_name("PHP EXIF Header Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=60150");
  script_xref(name : "URL" , value : "http://olex.openlogic.com/wazi/2011/php-5-4-0-medium/");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-4566");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
  ##To check PHP version prior to 5.4.0
  if(version_is_less(version:phpVer, test_version:"5.4.0")){
    security_hole(0);
  }
}
