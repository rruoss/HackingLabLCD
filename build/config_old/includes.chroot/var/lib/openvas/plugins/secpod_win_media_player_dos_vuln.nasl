###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_win_media_player_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Windows Media Player Denial Of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to cause denial of service.
  Impact Level: Application";
tag_affected = "Windows Media Player version 11.0.5721.5262";
tag_insight = "The flaw is caused to unspecified error in the application.";
tag_solution = "No solution or patch is available as of 29th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://windows.microsoft.com/en-US/windows/downloads/windows-media-player";
tag_summary = "This host is installed with Windows Media Player and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(902781);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"creation_date", value:"2011-12-27 18:30:35 +0530 (Tue, 27 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("Windows Media Player Denial Of Service Vulnerability");
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


  script_description(desc);
  script_summary("Check for Windows Media Player version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_require_keys("Win/MediaPlayer/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108152/wmp11-dos.txt");
  exit(0);
}


include("version_func.inc");

## Get the version
wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

## Check for Windows Media Player version 11.0.5721.5262
if(version_is_equal(version:wmpVer, test_version:"11.0.5721.5262")){
  security_hole(0);
}
