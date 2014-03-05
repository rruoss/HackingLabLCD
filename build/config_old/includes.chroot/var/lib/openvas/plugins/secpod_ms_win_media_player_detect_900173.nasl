##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_win_media_player_detect_900173.nasl 42 2013-11-04 19:41:32Z jan $
# Description: Microsoft Windows Media Player Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_summary = "This script find the Windows Media Player installed version and
  save the version in KB.";

if(description)
{
  script_id(900173);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Microsoft Windows Media Player Version Detection");
  script_summary("Set File Version of Windows Media Player in KB");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

keyX = "SOFTWARE\Microsoft\Active setup\Installed Components\";
 
# CLSID matchs with Win Media Player versions 7 or above
wmpVer = registry_get_sz(key:keyX + "{6BF52A52-394A-11d3-B153-00C04F79FAA6}",
                         item:"Version");
if(!wmpVer)
{
  wmpVer = registry_get_sz(key:keyX + "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}",
                           item:"Version");
  if(!wmpVer){
    exit(0);
  }
}

# For replacing comma (,) with dot (.)
wmpVer = ereg_replace(string:wmpVer, pattern:",", replace:".");

# Set the KB item for Windows Media Player.
set_kb_item(name:"Win/MediaPlayer/Ver", value:wmpVer);
security_note(data:"Microsoft Windows Media Player version " + wmpVer + 
                   " was detected on the host");

