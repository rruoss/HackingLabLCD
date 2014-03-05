###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# VLC Media Player Real Demuxer File Handling Array Indexing Vulnerabilities (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow the attackers to crash an affected application
  or compromise a vulnerable system by convincing a user to open a malicious media
  file or to visit a specially crafted web page.
  Impact Level: Application.";
tag_affected = "VLC Media Player version 1.1.5 and prior.";

tag_insight = "This issue is caused by an array indexing error in the 'Close()' and
  'DemuxAudioMethod1()' [modules/demux/real.c] functions within the Real
   demuxer when processing a Real Media file with a zero 'i_subpackets' value.";
tag_solution = "Upgrade to VLC version 1.1.6 or apply patch from below link,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC media player and is prone to
  array indexing vulnerabilities.";

if(description)
{
  script_id(801565);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-3907");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("VLC Media Player Real Demuxer File Handling Array Indexing Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1007.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3345");
  script_xref(name : "URL" , value : "http://www.cs.brown.edu/people/drosenbe/research.html");

  script_description(desc);
  script_summary("Check for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_require_keys("VLCPlayer/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}

include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(!vlcVer){
  exit(0);
}

# VLC Media Player Version 1.1.5 and prior.
if(version_is_less(version:vlcVer, test_version:"1.1.6")){
  security_hole(0);
}
