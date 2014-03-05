###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_watch_folders_bof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# RealPlayer Watch Folders Function Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system.
  Impact Level: System/Application";
tag_affected = "RealPlayer version 15.0.5.109";
tag_insight = "The 'Watch Folders' function fails to process an overly long directory
  path, which can be exploited to cause stack-based buffer overflow via a
  crafted ZIP file.";
tag_solution = "No solution or patch is available as of 06th November, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(803043);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4987");
  script_bugtraq_id(56324);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-06 12:38:20 +0530 (Tue, 06 Nov 2012)");
  script_name("RealPlayer Watch Folders Function Buffer Overflow Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/86721");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Oct/189");
  script_xref(name : "URL" , value : "http://www.reactionpenetrationtesting.co.uk/realplayer-watchfolders.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117691/Realplayer-Watchfolders-Long-Filepath-Overflow.html");

  script_description(desc);
  script_summary("Check for the version of RealPlayer on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
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

# Variable Initialization
rpVer = "";

#Get Version
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

## Check for Realplayer 15.0.5.109
if(version_is_equal(version:rpVer, test_version:"15.0.5.109")){
  security_hole(0);
}
