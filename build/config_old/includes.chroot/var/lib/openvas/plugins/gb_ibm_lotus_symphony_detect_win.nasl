###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_symphony_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# IBM Lotus Symphony Version Detection (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Foxit Reader.

The script logs in via smb, searches for Foxit Reader in the registry and
gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802226";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Foxit Reader Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of IBM Lotus Symphony");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
key = "";
item = "";
name = "";
version = "";
path = "";
cpe = "";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm IBM Lotus Symphony
if(!registry_key_exists(key:"SOFTWARE\Lotus\Symphony")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get Version From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("IBM Lotus Symphony" >< name)
  {
    version = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(version)
    {
      path = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!path){
        path = 'Could not find the install path from registry';
      }

      # Set IBM Lotus Symphony Version in KB
      set_kb_item(name:"IBM/Lotus/Symphony/Win/Ver", value:version);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:lotus_symphony:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:lotus_symphony";

      register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:"IBM Lotus Symphony",
                                               version:version, install:path,
                                               cpe:cpe, concluded: version));
      exit(0);
    }
  }
}
