###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_illustrator_mult_unspecified_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Illustrator Multiple Unspecified Vulnerabilities (Windows)
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
tag_solution = "Apply patch for Adobe Illustrator CS5 and CS5.5,
  For updates refer to http://www.adobe.com/support/security/bulletins/apsb12-10.html

  Or upgrade to Adobe Illustrator version CS6 or later,
  For updates refer to http://www.adobe.com/downloads/";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code
  or cause denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Illustrator version CS5.5 (15.1) on Windows.";
tag_insight = "The flaws are due to an multiple unspecified errors in the
  application.";
tag_summary = "This host is installed with Adobe Illustrator and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802790);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2026", "CVE-2012-2025", "CVE-2012-2024", "CVE-2012-2023",
                "CVE-2012-0780", "CVE-2012-2042");
  script_bugtraq_id(53422);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-16 17:55:09 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Illustrator Multiple Unspecified Vulnerabilities (Windows)");
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

  script_xref(name : "URL" , value : "http://osvdb.org/81758");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47118");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027047");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-10.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Illustrator on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
appkey = "";
illuVer = "";
appPath = "";

## Confirm appln is installed
appkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Illustrator.exe";
if(!registry_key_exists(key:appkey)) {
    exit(0);
}

## Get the installed path
appPath = registry_get_sz(key:appkey, item:"Path");
if(appPath)
{
  illuVer = fetch_file_version(sysPath:appPath, file_name:"Illustrator.exe");
  if(!illuVer){
    exit(0);
  }

  ## Check for Adobe Illustrator versions with patch
  ## Adobe Illustrator CS5.5 (15.1.1) and CS5 (15.0.3)
  if(version_is_less(version:illuVer, test_version:"15.0.3"))
  {
    security_hole(0);
    exit(0);
  }

  if("15.1" >< illuVer)
  {
    if(version_is_less(version:illuVer, test_version:"15.1.1")){
      security_hole(0);
    }
  }
}
