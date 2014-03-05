###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuance_pdf_reader_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Nuance PDF Reader Version Detection (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Nuance PDF Reader.

The script logs in via smb, searches for Nuance PDF Reader in the
registry and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803328";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-11 15:20:19 +0530 (Mon, 11 Mar 2013)");
  script_name("Nuance PDF Reader Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Nuance PDF Reader on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
ReaderName = "";
ReaderPath = "";
ReaderVer = "";
cpe = "";
key = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for the Name
  ReaderName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Nuance PDF Reader" >< ReaderName)
  {
    ## Check for the install path
    ReaderPath =registry_get_sz(key:key + item, item:"InstallLocation");
    if(!ReaderPath){
      ReaderPath = "Could not find the install Location";
    }

    ## Check for the version
    ReaderVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ReaderVer)
    {
      set_kb_item(name:"Nuance/PDFReader/Win/Ver", value:ReaderVer);

      ## Build cpe
      cpe = build_cpe(value:ReaderVer, exp:"^([0-9.]+)",
                      base:"cpe:/a:nuance:pdf_reader:");
      if(isnull(cpe))
        cpe = "cpe:/a:nuance:pdf_reader";

      register_product(cpe:cpe, location:ReaderPath, nvt:SCRIPT_OID);
      log_message(data: build_detection_report(app:"Nuance PDF Reader",
                                        version:ReaderVer, install:ReaderPath,
                                        cpe:cpe, concluded:ReaderVer));
      exit(0);
    }
  }
}
