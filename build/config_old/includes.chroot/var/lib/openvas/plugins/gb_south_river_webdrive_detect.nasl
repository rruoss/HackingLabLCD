###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_south_river_webdrive_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# South River WebDrive Version Detection
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed South River WebDrive and
  saves the version in KB.";

if(description)
{
  script_id(800158);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("South River WebDrive Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of South River WebDrive in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800158";
SCRIPT_DESC = "South River WebDrive Version Detection";

## Windows Confirmation
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## South River Web Drive Application confirmation
if(!registry_key_exists(key:"SOFTWARE\South River Technologies\WebDrive")){
  exit(0);
}

## Get the South River Web Drive Version
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  webDrive = registry_get_sz(key:key + item, item:"DisplayName");
  if("WebDrive" >< webDrive)
  {
    webDriveVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if( webDriveVer != NULL)
    {
       set_kb_item(name:"SouthRiverWebDrive/Win/Ver", value:webDriveVer);
       security_note(data:"South River WebDrive version " + webDriveVer +
                         " was detected on the host");
      
       ## build cpe and store it as host_detail
       cpe = build_cpe(value:webDriveVer, exp:"^([0-9.]+)", base:"cpe:/a:south_river_technologies:webdrive:");
       if(!isnull(cpe))
          register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
