###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_media_player_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will lets attacker execute arbitrary codes in
  the context of the affected player.
  Impact Level: System/Application";
tag_affected = "Windows Media Player version 9.x and 11 to 11.0.5721.5145.";
tag_insight = "This flaw is due to a boundary checking error while opening a
  specially-crafted '.mpg' audio files.";
tag_solution = "No solution or patch is available as of 01st March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/windowsmedia/default.mspx";
tag_summary = "The host is installed with Windows Media Player and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(800480);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:36:32 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0718");
  script_name("Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56435");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11531");

  script_description(desc);
  script_summary("Check for the Version of Windows Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_require_keys("Win/MediaPlayer/Ver");
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

wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

if(wmpVer =~ "^(9|11)\..*$")
{
  # Check for Windows Media Player version 9.x, 11 to 11.0.5721.5145
  if(version_in_range(version:wmpVer, test_version:"9.0", test_version2:"9.0.0.4503") ||
     version_in_range(version:wmpVer, test_version:"11.0", test_version2:"11.0.5721.5145")){
    security_warning(0);
  }
}
