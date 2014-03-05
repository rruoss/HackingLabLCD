###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_detect_win.nasl 42 2013-11-04 19:41:32Z jan $
#
# Wireshark Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-27
# According to cr57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800038";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Wireshark Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Wireshark on Windows.

The script logs in via smb, searches for Wireshark in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
wiresharkVer = "";
wireName = "";
path = "";
cpe = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

wireName = registry_get_sz(key: key + "Wireshark", item:"DisplayName");

## Confirm Wireshark
if("Wireshark" >< wireName)
{
  ## Get the Version
  wiresharkVer = registry_get_sz(key: key + "Wireshark", item:"DisplayVersion");

  path = registry_get_sz(key: key + "Wireshark", item:"UninstallString");
  if(path){
    path = path - "\uninstall.exe";
  } else {
    path = "Unable to find the install location from registry.";
  }

  if(wiresharkVer)
  {
    set_kb_item(name:"Wireshark/Win/Ver", value:wiresharkVer);

    ## Build cpe
    cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(isnull(cpe))
      cpe = 'cpe:/a:wireshark:wireshark';

    register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

    log_message(data: build_detection_report(app: wireName,
                                             version: wiresharkVer,
                                             install: path,
                                             cpe: cpe,
                                             concluded: wiresharkVer));
  }
}
