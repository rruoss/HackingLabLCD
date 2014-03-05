##############################################i#################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_jan10_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Reader/Acrobat Multiple Vulnerabilities -jan10 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause memory corruption or
  denial of service.

  Impact level: System/Application.";

tag_solution = "Apply the patch or upgrade Adobe Reader and Acrobat 8.2, 9.3,
  http://www.adobe.com/downloads/
  http://www.adobe.com/support/security/bulletins/apsb10-02.html

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****";

tag_affected = "Adobe Reader and Acrobat 9.x before 9.3 , 8.x before 8.2 on Windows.";
tag_insight = "For more information refer the references section.";
tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800427);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3953", "CVE-2009-3954", "CVE-2009-3955", "CVE-2009-3956",
                "CVE-2009-3957", "CVE-2009-3958", "CVE-2009-3959", "CVE-2009-4324",
                "CVE-2010-1278");
  script_bugtraq_id(37758, 37761, 37757, 37763, 37760, 37759, 37756);
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities - Jan10 (Win)");
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

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-02.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Reader/Win/Ver", "Adobe/Acrobat/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Win/Ver");
acroVer = get_kb_item("Adobe/Acrobat/Win/Ver");

if(readerVer != NULL)
{
  # Grep for Adobe Reader version prior to 9.x, 8.x
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.2") ||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2")){
    security_hole(0);
  }
}

if(acroVer != NULL)
{
  # Grep for Adobe Acrobat version prior to 9.x, 8.x
  if(version_in_range(version:acroVer, test_version:"9.0", test_version2:"9.2") ||
     version_in_range(version:acroVer, test_version:"8.0", test_version2:"8.2")){
    security_hole(0);
  }
}
