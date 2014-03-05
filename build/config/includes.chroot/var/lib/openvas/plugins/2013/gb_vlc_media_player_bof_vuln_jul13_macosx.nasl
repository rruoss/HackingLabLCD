###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_bof_vuln_jul13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# VLC Media Player Buffer Overflow Vulnerability - July 13 (MAC OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "
  Impact Level: System/Application";

if(description)
{
  script_id(803699);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1954");
  script_bugtraq_id(57333);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-16 13:56:02 +0530 (Tue, 16 Jul 2013)");
  script_name("VLC Media Player Buffer Overflow Vulnerability - July 13 (MAC OS X)");

  tag_summary =
"This host is installed with VLC Media Player and is prone to
buffer overflow vulnerability.";

  tag_insight =
"Flaw due to error in 'DemuxPacket()' function in the ASF Demuxer component
(modules/demux/asf/asf.c) when parsing ASF files.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_impact =
"Successful exploitation could allow attackers to execute arbitrary code or
cause denial of service condition in the context of affected application via
crafted ASF file.";

  tag_affected =
"VLC media player version 2.0.5 and prior on MAC OS X";

  tag_solution =
"Upgrade to VLC media player version 2.0.6 or later,
For updates refer to http://www.videolan.org/vlc";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/89598");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51995");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1302.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of VLC Media Player on MAC OS X");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
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

## Check for VLC Media Player Version <= 2.0.5
if(version_is_less_equal(version:vlcVer, test_version:"2.0.5"))
{
  security_hole(0);
  exit(0);
}
