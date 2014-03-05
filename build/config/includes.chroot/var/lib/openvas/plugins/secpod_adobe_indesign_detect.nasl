###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_indesign_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe InDesign Version Detection
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
tag_summary = "This host is installed with Adobe InDesign and sets the
  result in KB.";

if(description)
{
  script_id(902084);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Adobe InDesign Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Adobe InDesign Version in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902084";
SCRIPT_DESC = "Adobe InDesign Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe\InDesign")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  adName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Adobe InDesign" >< adName)
  {
    ## Get the installed location from registry
    adPath = registry_get_sz(key:key + item, item:"InstallLocation");

    ## Get Adobe InDesign version from registry
    adVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(adVer != NULL)
    {
      tmp_version = adName + " " + adVer;
      set_kb_item(name:"Adobe/InDesign/Ver", value:tmp_version);
      security_note(data:adName + " version " + adVer + " installed at location " +
                       adPath + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_cs3:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}