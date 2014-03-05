###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_bof_vuln_feb11_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# VLC Media Player USF and Text Subtitles Decoders BOF Vulnerabilities (Linux)
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
tag_impact = "Successful exploitation could allow attackers to crash an affected application
  or execute arbitrary by convincing a user to open a malicious media file.
  Impact Level: Application";
tag_affected = "VLC media player version 1.x before 1.1.6-rc";
tag_insight = "The flaws are caused by buffer overflow errors in the 'StripTags()' function
  within the USF and Text subtitles decoders 'modules/codec/subtitles/subsdec.c'
  and 'modules/codec/subtitles/subsusf.c' when processing malformed data.";
tag_solution = "Upgrade to the VLC media player version 1.1.6-rc or later,
  For updates refer to http://download.videolan.org/pub/videolan/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone to
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(902342);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0522");
  script_bugtraq_id(46008);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("VLC Media Player USF and Text Subtitles Decoders BOF Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65029");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16108/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0225");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Check for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_require_keys("VLCPlayer/Lin/Ver");
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

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version less than 1.1.6
if(version_in_range(version:vlcVer, test_version:"1.1", test_version2:"1.1.6")){
  security_hole(0);
}
