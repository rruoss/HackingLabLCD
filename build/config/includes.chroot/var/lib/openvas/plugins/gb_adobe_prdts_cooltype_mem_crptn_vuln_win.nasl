###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_cooltype_mem_crptn_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Upgrade to Adobe Reader version 9.4.4 or Acrobat 9.4.4 or 10.0.3
  For updates refer to http://www.adobe.com

  *****
  NOTE : No fix available for Adobe Reader X (10.x), vendors are planning to
         address this issue in next quarterly security update for Adobe Reader.
  *****";

tag_impact = "Successful exploitation will let attackers to crash an affected application
  or compromise a vulnerable system by tricking a user into opening a specially
  crafted PDF file.
  Impact Level:Application";
tag_affected = "Adobe Reader version prior to 9.4.4 and 10.x to 10.0.1
  Adobe Acrobat version prior to 9.4.4 and 10.x to 10.0.2 on windows";
tag_insight = "This issue is caused by a memory corruption error in the 'CoolType' library
  when processing the malformed Flash content within a PDF document.";
tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  memory corruption and reemote code execution vulnerability";

if(description)
{
  script_id(801933);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-0610");
  script_bugtraq_id(47531);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0923");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-08.html");

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
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer)
{
  # Check for Adobe Reader version < 9.4.4 and 10.x to 10.0.1
  if(version_is_less(version:readerVer, test_version:"9.4.4") ||
    version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.1"))
  {
    security_hole(0);
    exit(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  # Check for Adobe Acrobat version < 9.4.4 and 10.x to 10.0.2
  if(version_is_less(version:acrobatVer, test_version:"9.4.4") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.2")){
    security_hole(0);
  }
}
