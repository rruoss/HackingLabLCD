###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_virusscan_enterprise_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# McAfee VirusScan Enterprise Version Detection (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of McAfee VirusScan Enterprise.

The script detects the version of McAfee VirusScan Enterprise and sets the
version in KB";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803319";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-04 09:45:42 +0530 (Mon, 04 Mar 2013)");
  script_name("McAfee VirusScan Enterprise Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Set the Version of McAfee VirusScan Enterprise in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
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

## Variable Initialization
key = "";
name = "";
path = "";
version = "";
version1 = "";
cpe = "";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application
key = "SOFTWARE\McAfee\DesktopProtection";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Function to set KB and Build CPE
function SetCpeMvs(version, path, regex)
{
  set_kb_item(name:"McAfee/VirusScan/Win/Ver", value:version);

  ## Build cpe
  cpe = build_cpe(value:version, exp:regex,
        base:"cpe:/a:mcafee:virusscan_enterprise:");
  if(isnull(cpe))
   cpe = 'cpe:/a:mcafee:virusscan_enterprise';

  register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
  log_message(data: build_detection_report(app:"McAfee VirusScan Enterprise",
                                           version:version, install:path,
                                           cpe:cpe, concluded:version));
}

## Get Product Name
name = registry_get_sz(key:key, item:"Product");
if("McAfee VirusScan Enterprise" >< name)
{
  ##Get version
  version = registry_get_sz(key:key, item:"szProductVer");
  if(version)
  {
    ## Get Install Path
    path =registry_get_sz(key:key, item:"szInstallDir");
    if(path)
    {
      path += "readme.txt";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
      txtRead = read_file(share:share, file:file, offset:0, count:500000);

      ## Get Version
      version1 = eregmatch(pattern:"Version ([0-9.]+[a-z])", string:txtRead);
      if(version1[1]){
        SetCpeMvs(version:version1[1], path:path, regex:"^([0-9.]+[a-z])");
      }
      else{
        SetCpeMvs(version:version, path:path, regex:"^([0-9.]+)");
      }
    }
  }
}
