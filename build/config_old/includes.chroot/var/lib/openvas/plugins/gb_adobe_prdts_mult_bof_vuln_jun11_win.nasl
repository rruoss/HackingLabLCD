###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_bof_vuln_jun11_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader and Acrobat Multiple BOF Vulnerabilities June-2011 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let local attackers to application to crash and
  potentially take control of the affected system.
  Impact Level: System/Application";
tag_affected = "Adobe Acrobat version 8.0 to 8.2.6, 9.0 to 9.4.4 and 10.0 to 10.0.3
  Adobe Reader version 8.0 to 8.2.6, 9.0 to 9.4.4 and 10.0 to 10.0.3";
tag_insight = "Multiple flaws are caused by buffer overflow errors in the applications,
  which allows attackers to execute arbitrary code via unspecified vectors.";
tag_solution = "Upgrade to Adobe Acrobat and Reader version 10.1, 9.4.5 or 8.3 or later
  For updates refer to http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows";
tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  multiple buffer overflow vulnerabilities.";

if(description)
{
  script_id(802110);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2094", "CVE-2011-2095", "CVE-2011-2096", "CVE-2011-2097",
                "CVE-2011-2098", "CVE-2011-2099", "CVE-2011-2100", "CVE-2011-2101",
                "CVE-2011-2104", "CVE-2011-2105", "CVE-2011-2106");
  script_bugtraq_id(48240, 48242, 48243, 48244, 48245, 48246, 48252, 48255, 48251,
                    48248, 48249);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader and Acrobat Multiple BOF Vulnerabilities June-2011 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-16.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Acrobat/Win/Ver", "Adobe/Reader/Win/Ver");
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

readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer != NULL)
{
  ## Check for Adobe Reader versions
  if(version_in_range(version:readerVer, test_version:"8.2", test_version2:"8.2.6")||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.4") ||
     version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.3"))
  {
    security_hole(0);
    exit(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer != NULL)
{
  ## Check for Adobe Acrobat versions
  if(version_in_range(version:acrobatVer, test_version:"8.2", test_version2:"8.2.6")||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.4.4") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.3")){
    security_hole(0);
  }
}
