###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xilisoft_video_conv_detect.nasl 1904 2009-04-23 90:07:05Z apr$
#
# Xilisoft Video Converter Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 secpod http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "The script will detects the Xilisoft Video Converter installed
  on this host and sets the version in KB.";

if(description)
{
  script_id(900629);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Xilisoft Video Converter Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for the version of Xilisoft Video Converter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900629";
SCRIPT_DESC = "Xilisoft Video Converter Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  xilisoftName= registry_get_sz(item:"DisplayName", key:key +item);
  xilisoftConf = registry_get_sz(item:"UninstallString", key:key + item);

  if(("Video Converter" >< xilisoftName) && ("Xilisoft" >< xilisoftConf))
  {
    xilisoftVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(xilisoftVer != NULL){
      set_kb_item(name:"Xilisoft/Video/Conv/Ver", value:xilisoftVer);
      security_note(data:"Xilisoft Video Converter version " + xilisoftVer +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:xilisoftVer, exp:"^([0-9]\.[0-9]\.[0-9]+)", base:"cpe:/a:xilisoft:xilisoft_video_converter:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
