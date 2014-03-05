###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_detect_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Picasa Version Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Rachana Shetty <srachana@secpod.com> on 2011-08-02
#  - Updated to detect build version from .exe file.
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed version of Google Picasa and
  sets the result in KB.";

if(description)
{
  script_id(801769);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Google Picasa Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Google Picasa in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Google\Picasa")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  picName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("Picasa" >< picName)
  {
    ## Check for the install path
    picPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(!isnull(picPath))
    {
      picPath = ereg_replace(pattern:'"', replace:"", string:picPath);
      picPath = picPath - "\Uninstall.exe";

      ## Check for moviethumb (original picasa.exe) file version
      picVer = fetch_file_version(sysPath:picPath, file_name:"moviethumb.exe");
      if(!isnull(picVer))
      {
        ## Set the KB item
        set_kb_item(name:"Google/Picasa/Win/Ver", value:picVer);
        security_note(data:"Google Picasa version " + picVer +
                         " was detected on the host");
      }
    }
  }
}
