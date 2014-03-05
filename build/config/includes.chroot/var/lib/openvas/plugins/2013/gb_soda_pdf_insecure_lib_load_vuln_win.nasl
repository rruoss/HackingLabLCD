###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soda_pdf_insecure_lib_load_vuln_win.nasl 31536 2013-09-03 14:36:51Z sep$
#
# Soda PDF Insecure Library Loading Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803751";
CPE = "cpe:/a:soda:soda_pdf";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3485");
  script_bugtraq_id(61727);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-03 11:21:22 +0530 (Tue, 03 Sep 2013)");
  script_name("Soda PDF Insecure Library Loading Vulnerability (Windows)");

  tag_summary =
"The host is installed with Soda PDF and is prone to insecure library
loading vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to the application loading libraries (dwmapi.dll or
api-ms-win-core-localregistry-l1-1-0.dll) in an insecure manner.";

  tag_impact =
"Successful exploitation will allow local attacker to execute arbitrary code
and conduct DLL hijacking attacks.

Impact Level: System/Application";

  tag_affected =
"Soda PDF version 5.1.183.10520, Other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 03rd September, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://sodapdf.com";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/96228");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53207");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/86353");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5486855.html");
  script_summary("Check for the vulnerable version of Soda PDF on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_soda_pdf_detect_win.nasl");
  script_mandatory_keys("Soda/PDF/Ver/Win");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
sodaPdfVer = "";

## Get version from KB
sodaPdfVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!sodaPdfVer){
  exit(0);
}

## Check for version
if(version_is_equal(version:sodaPdfVer, test_version:"5.1.183.10520"))
{
  security_hole(0);
  exit(0);
}
