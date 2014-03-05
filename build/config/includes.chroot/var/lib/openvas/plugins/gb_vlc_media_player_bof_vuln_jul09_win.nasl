###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_bof_vuln_jul09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# VLC Media Player SMB 'Win32AddConnection()' BOF Vulnerability - July09 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply the available patch from below link,
  http://git.videolan.org/?p=vlc.git;a=commit;h=e60a9038b13b5eb805a76755efc5c6d5e080180f

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to execute arbitrary code, and can
  casue application crash.
  Impact Level: Application";
tag_affected = "VLC Media Player version 0.9.9 and prior on Windows.";
tag_insight = "Stack-based Buffer overflow error in the 'Win32AddConnection' function in
  modules/access/smb.c while processing a specially crafted long 'smb://' URI
  within a playlist.";
tag_summary = "This host is installed with VLC Media Player and is prone to
  Stack-Based Buffer Overflow Vulnerability.";

if(description)
{
  script_id(800663);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2484");
  script_bugtraq_id(35500);
  script_name("VLC Media Player SMB 'Win32AddConnection()' BOF Vulnerability - July09 (Win)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/35558");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9029");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1714");

  script_description(desc);
  script_summary("Check for the Version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_require_keys("VLCPlayer/Win/Ver");
  script_require_ports("Services/www");
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

vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(vlcVer != NULL)
{
  if(version_is_less_equal(version:vlcVer, test_version:"0.9.9")){
    security_hole(0);
  }
}
