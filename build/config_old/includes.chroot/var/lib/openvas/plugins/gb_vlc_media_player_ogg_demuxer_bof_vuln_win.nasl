###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_ogg_demuxer_bof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# VLC Media Player OGG Demuxer Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code on
  the target system.
  Impact Level: Application/System";
tag_affected = "VLC media player versions prior to 2.0.2 on Windows";
tag_insight = "A boundary error exists within the 'Ogg_DecodePacket()' function
  (modules/demux/ogg.c) when processing OGG container files. This can be
  exploited to cause heap-based buffer overflow via a specially crafted OGG
  file.";
tag_solution = "Upgrade to VLC media player version 2.0.2 or later
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC Media Player and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(802922);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3377");
  script_bugtraq_id(54345);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-25 14:01:24 +0530 (Wed, 25 Jul 2012)");
  script_name("VLC Media Player OGG Demuxer Buffer Overflow Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83615");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49835");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/76800");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1027224");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/07/06/1");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/07/06/2");
  script_xref(name : "URL" , value : "http://git.videolan.org/?p=vlc/vlc-2.0.git;a=commitdiff;h=16e9e126333fb7acb47d363366fee3deadc8331e");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check for the version of VLC Media Player on Windows");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_require_keys("VLCPlayer/Win/Ver");
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

## Variable Initialization
vlcVer = "";

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version prior to 2.0.2
if(version_is_less(version:vlcVer, test_version:"2.0.2")){
  security_hole(0);
}
