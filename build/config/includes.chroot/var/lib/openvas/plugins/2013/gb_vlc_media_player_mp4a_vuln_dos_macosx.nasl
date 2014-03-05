###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mp4a_vuln_dos_macosx.nasl 66 2013-11-15 15:53:31Z veerendragg $
#
# VLC Media Player mp4a Denial of Service Vulnerability (MAC OS X)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803955";
CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 66 $");
  script_cve_id("CVE-2013-4388");
  script_bugtraq_id(62724);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-15 16:53:31 +0100 (Fri, 15 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-10-22 19:02:32 +0530 (Tue, 22 Oct 2013)");
  script_name("VLC Media Player mp4a Denial of Service Vulnerability (MAC OS X)");

  tag_summary =
"This host is installed with VLC Media Player and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"A flaw exist in mpeg4audio.c file, which to perform adequate boundary checks
on user-supplied input. ";

  tag_impact =
"Successful exploitation will allow attackers to overflow buffer, cause denial
of service.

Impact Level: Application";

  tag_affected =
"VLC media player version 2.0.7 and prior on MAC OS X";

  tag_solution =
"Upgrade to VLC media player version 2.0.8 or later,
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

  Impact Level: System/Application

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
  script_xref(name : "URL" , value : "http://www.videolan.org/news.html");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1029120");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/10/01/2");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of VLC Media Player on MAC OS X");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
vlcVer = "";

## Get the VLC version
vlcVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version <= 2.0.7
if(version_is_less_equal(version:vlcVer, test_version:"2.0.7"))
{
  security_hole(0);
  exit(0);
}
