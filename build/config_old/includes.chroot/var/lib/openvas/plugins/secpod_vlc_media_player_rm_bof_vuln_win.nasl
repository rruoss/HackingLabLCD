###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_rm_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# VLC Media Player '.RM' File BOF Vulnerability (Windows)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions.
  Impact Level: Application";
tag_affected = "VLC media player version 1.1.0 to 1.1.10 on Windows.";
tag_insight = "The flaw is due to missing input validation when allocating memory
  using certain values from a RealAudio data block within RealMedia (RM)
  files.";
tag_solution = "Upgrade to the VLC media player version 1.1.11 or later,
  For updates refer to http://www.videolan.org/";
tag_summary = "The host is installed with VLC Media Player and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(902704);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-2587");
  script_bugtraq_id(48664);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("VLC Media Player '.RM' File BOF Vulnerability (Windows)");
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
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Check for the version of VLC Media Player");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45066");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68531");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1105.html");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version
if(version_in_range(version:vlcVer, test_version:"1.1.0", test_version2:"1.1.10")){
  security_hole(0);
}
