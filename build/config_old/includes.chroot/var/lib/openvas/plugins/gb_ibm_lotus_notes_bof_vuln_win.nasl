###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM Lotus Notes Buffer Overflow Vulnerability (Win)
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in the
  context of the user running the application. Failed exploit attempts will result
  in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "IBM Lotus Notes Version 8.0 and 8.5 to 8.5 FP1 on Windows.";
tag_insight = "The flaw is due to an unspecified error in application, which fails to adequately
  perform boundary checks on user supplied data and can be exploited to cause a
  stack based buffer overflow.";
tag_solution = "No solution or patch is available as of 04th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ibm.com/software/lotus/products/notes/";
tag_summary = "This host has IBM Lotus Notes installed and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(801327);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1608");
  script_bugtraq_id(38300);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Notes Buffer Overflow Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38622");
  script_xref(name : "URL" , value : "https://forum.immunityinc.com/board/thread/1161/vulndisco-9-0/");

  script_description(desc);
  script_summary("Check for the version of IBM Lotus Notes");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_require_keys("IBM/LotusNotes/Win/Ver");
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

# Get for IBM Lotus Notes Version
lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(lotusVer != NULL)
{
  # Check for  IBM Lotus Notes version 8.0 and 8.5 fp1 <= 8.5.1.9167
  if(version_is_equal(version:lotusVer, test_version:"8.0") ||
     version_in_range(version:lotusVer, test_version:"8.5", test_version2:"8.5.1.9167")){
    security_hole(0);
  }
}
