###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_code_exec_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# VLC Media Player '.mkv' Code Execution Vulnerability (Linux)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted MKV file.
  Impact Level: Application";
tag_affected = "VLC media player version 1.1.6.1 and prior on Linux";
tag_insight = "The flaw is due to an input validation error within the 'MKV_IS_ID'
  macro in 'modules/demux/mkv/mkv.hpp' of the MKV demuxer, when parsing the
  MKV file.";
tag_solution = "Upgrade to the VLC media player version 1.1.7 or later,
  For updates refer to http://download.videolan.org/pub/videolan/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone to
  arbitrary code execution vulnerability.";

if(description)
{
  script_id(902339);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0531");
  script_bugtraq_id(46060);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("VLC Media Player '.mkv' Code Execution Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70698");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65045");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1025018");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Check for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

## Check for VLC Media Player Version less than 1.1.7
if(version_is_less(version:vlcVer, test_version:"1.1.7")){
  security_hole(0);
}
