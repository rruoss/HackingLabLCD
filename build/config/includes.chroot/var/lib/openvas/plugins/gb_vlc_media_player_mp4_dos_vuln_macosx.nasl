###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mp4_dos_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# VLC Media Player 'MP4' Denial of Service Vulnerability (Mac OS X)
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
tag_impact = "Successful exploitation could allow attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "VLC media player version 2.0.1 on Mac OS X.";
tag_insight = "A division by zero error exists when handling MP4 files, which can be
  exploited to cause a crash.";
tag_solution = "No solution or patch is available as of 25th July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC Media Player and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802921);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2396");
  script_bugtraq_id(53535, 53169);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-25 13:33:36 +0530 (Wed, 25 Jul 2012)");
  script_name("VLC Media Player 'MP4' Denial of Service Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/81224");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49159");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75038");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18757");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111991/VLC-2.0.1-Division-By-Zero.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check for the version of VLC Media Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_require_keys("VLC/Media/Player/MacOSX/Version");
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
vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version is 2.0.1
if(version_is_equal(version:vlcVer, test_version:"2.0.1")){
  security_warning(0);
}
