###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_swf_mult_code_exec_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Flash Player 'SWF' File Multiple Code Execution Vulnerability - Mac OS X
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application.
  Impact Level: Application.";
tag_affected = "Adobe Flash Player version 11.1.102.55 on MAC OS X";
tag_insight = "The flaws are due to an unspecified error in the application, allows
  remote attackers to execute arbitrary code via a crafted SWF file.";
tag_solution = "No solution or patch is available as of 09th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/support/flashplayer/downloads.html";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple arbitrary code execution vulnerabilities.";

if(description)
{
  script_id(802541);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4694", "CVE-2011-4693");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 11:41:37 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Flash Player 'SWF' File Multiple Code Execution Vulnerability - Mac OS X");
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
  script_xref(name : "URL" , value : "http://partners.immunityinc.com/movies/VulnDisco-Flash0day-v2.mov");
  script_xref(name : "URL" , value : "https://lists.immunityinc.com/pipermail/dailydave/2011-December/000402.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Flash/Player/MacOSX/Version");
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

# Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_equal(version:playerVer, test_version:"11.1.102.55")){
    security_hole(0);
  }
}