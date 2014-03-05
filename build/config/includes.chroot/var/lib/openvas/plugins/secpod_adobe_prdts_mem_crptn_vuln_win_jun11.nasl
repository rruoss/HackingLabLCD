###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_mem_crptn_vuln_win_jun11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader/Acrobat Memory Corruption Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code in the
  context of the user running the affected application.
  Impact Level: System/Application";
tag_summary = "This host has Adobe Reader/Acrobat installed, and is/are prone
  to memory corruption vulnerability.";

tag_affected = "Adobe Reader version 8.x through 8.2.6
  Adobe Acrobat version 8.x through 8.2.6";
tag_insight = "The flaw is due to an unspecified error, which leads to memory
  corruption.";
tag_solution = "Upgrade to Adobe Acrobat and Reader version 8.3 or later.
  For updates refer to http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows";

if(description)
{
  script_id(902379);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2103");
  script_bugtraq_id(48247);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader/Acrobat Memory Corruption Vulnerability (Windows)");
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
  script_copyright("Copyright (C) 2011 SecPod");
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
  if(version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2.6"))
  {
    security_hole(0);
    exit(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer != NULL)
{
  ## Check for Adobe Acrobat versions
  if(version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.2.6")){
   security_hole(0);
  }
}
