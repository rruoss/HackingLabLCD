###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Foxit Reader Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Foxit Reader.

The script logs in via smb, searches for Foxit Reader in the registry and
gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800536";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Foxit Reader Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Foxit Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cpe = "";
foxitVer = "";
foxitPath = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

foxitVer = registry_get_sz(key:"SOFTWARE\Foxit Software\Foxit Reader",
                           item:"Version");
if(foxitVer == NULL)
{
  foxitPath = registry_get_sz(key:"SOFTWARE\Foxit Software\Foxit Reader",
                              item:"InstallLocation");
  if(foxitPath){
     foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
  }

  else
  {
    foxitPath = registry_get_sz(key:"SOFTWARE\Foxit Software\Foxit Reader",
                              item:"InnoSetupUpdatePath");
    if(foxitPath)
    {
      foxitPath = foxitPath - "unins000.exe";
      foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
    }
  }
}

if(foxitVer)
{
  set_kb_item(name:"Foxit/Reader/Ver", value:foxitVer);

  if(!foxitPath){
    foxitPath = 'Could not find the install path from registry';
  }
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
  if(isnull(cpe))
    cpe = "cpe:/a:foxitsoftware:reader";

  register_product(cpe:cpe, location:foxitPath, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app:"Foxit Reader",
                                           version:foxitVer, install:foxitPath,
                                           cpe:cpe, concluded: foxitVer));
}
