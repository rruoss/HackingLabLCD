###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blackberry_desktop_software_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# BlackBerry Desktop Software Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of BlackBerry Desktop
  Software and sets the result in KB.";

if(description)
{
  script_id(902311);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("BlackBerry Desktop Software Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of BlackBerry Desktop Software in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902311";
SCRIPT_DESC = "BlackBerry Desktop Software Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  bbdName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("BlackBerry Desktop Software" >< bbdName)
  {
    ## Check for the version
    bbdVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if (bbdVer != NULL)
    {
      ## Set the KB item
      set_kb_item(name:"BlackBerry/Desktop/Win/Ver", value:bbdVer);
      security_note(data:"BlackBerry Desktop Software version " + bbdVer +
                         " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:bbdVer, exp:"^([0-9.]+)", base:"cpe:/a:rim:blackberry_desktop_software:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
