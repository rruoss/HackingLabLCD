###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tvp_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Total Video Player Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause stack overflow to make the resource
  unavailable.
  Impact Level: Application";
tag_affected = "Total Video Player version 1.31 and prior on Windows.";
tag_insight = "This flaw is due to improper boundary check at 'DefaultSkin.ini' in the
  ColumnHeaderSpan value which copies data to an insufficiently sized memory
  buffer.";
tag_solution = "No solution or patch is available as of 30th January, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.effectmatrix.com/total-video-player/index.htm";
tag_summary = "This host is installed with Total Video Player and is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_id(900454);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0261");
  script_bugtraq_id(33373);
  script_name("Total Video Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7839");

  script_description(desc);
  script_summary("Check for the version of Total Video Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_tvp_detect.nasl");
  script_require_keys("TotalVideo/Player/Ver");
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

tvpVer = get_kb_item("TotalVideo/Player/Ver");
if(!tvpVer){
  exit(0);
}

# Check for Total Video Player version 1.31 and prior
if(version_is_less_equal(version:tvpVer, test_version:"1.31")){
  security_hole(0);
}
