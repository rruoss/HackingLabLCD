###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_libpng_plugin_dos_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# VLC Media Player 'libpng_plugin' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to crash the affected
  application and denying service to legitimate users.
  Impact Level: Application";
tag_affected = "VLC media player version 2.0.3 and prior on Mac OS X";
tag_insight = "The flaw is due to an error in 'libpng_plugin' when handling a crafted PNG
  file. Which can be exploited to cause a crash.";
tag_solution = "Upgrade to VLC media player 2.0.4 or later,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC Media Player and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802489);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5470");
  script_bugtraq_id(55850);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-02 14:31:32 +0530 (Fri, 02 Nov 2012)");
  script_name("VLC Media Player 'libpng_plugin' Denial of Service Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/86685");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21889/");
  script_xref(name : "URL" , value : "http://www.videolan.org/vlc/releases/2.0.4.html");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/10/24/3");

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

## Check for VLC Media Player Version is less than 2.0.4
if(version_is_less(version:vlcVer, test_version:"2.0.4")){
  security_warning(0);
}
