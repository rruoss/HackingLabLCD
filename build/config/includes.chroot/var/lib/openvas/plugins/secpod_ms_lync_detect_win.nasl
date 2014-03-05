###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_lync_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft Lync Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_summary = "Detection of installed version of Microsoft Lync.

The script logs in via smb, searches for Microsoft Lync in the registry and
gets the version from 'DisplayVersion' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902843";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-06-13 12:12:12 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Lync Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Microsoft Lync");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
path = "";
lyncName = "";
ver = NULL;
cpe = NULL;

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Lync version from registry
foreach item (registry_enum_keys(key:key))
{
  lyncName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Microsoft Office Communicator" >< lyncName || "Microsoft Lync" >< lyncName)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver)
    {
      ## Get Install Location
      path = registry_get_sz(key:key + item, item:"InstallLocation");
      if(! path){
        continue;
      }

      ## Check for Microsoft Lync Attendant
      if("Attendant" >< lyncName)
      {
        ## Set Version in KB
        set_kb_item(name:"MS/Lync/Attendant/Ver", value:ver);

        ## Set Path in KB, it may required in vulnerable plugin
        set_kb_item(name:"MS/Lync/Attendant/path", value:path);
      }

      ## Check for Microsoft Lync Attendee
      else if("Attendee"  >< lyncName)
      {
        ## Set Version in KB
        set_kb_item(name:"MS/Lync/Attendee/Ver", value:ver);

        ## Set Path in KB
        set_kb_item(name:"MS/Lync/Attendee/path", value:path);
      }
      else
      {
        ## Set Version in KB
        set_kb_item(name:"MS/Lync/Ver", value:ver);

        ## Set Path in KB
        set_kb_item(name:"MS/Lync/path", value:path);

        ## Build CPE
        cpe = build_cpe(value:ver, exp:"^([0-9.]+)",
                        base:"cpe:/a:microsoft:office_communicator:");
      }

      if(!isnull(cpe))
        register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:lyncName, version:ver,
                  install:path, cpe:cpe, concluded:ver));
    }
  }
}
