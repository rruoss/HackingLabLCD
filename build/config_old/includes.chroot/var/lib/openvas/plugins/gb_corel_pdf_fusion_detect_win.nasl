###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_corel_pdf_fusion_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Corel PDF Fusion Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804108";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-15 20:26:57 +0530 (Tue, 15 Oct 2013)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Corel PDF Fusion Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Corel PDF Fusion on Windows.

The script logs in via smb, searches for Corel PDF Fusion in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set version of Corel PDF Fusion in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable initialization
appName = "";
insPath = "";
pdfVer = "";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm for corel pdf fusion
  if("Corel PDF Fusion" >< appName)
  {
    pdfVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pdfVer)
    {
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insPath){
        insPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"Corel/PDF/Fusion/Win/Ver", value: pdfVer);

      ## build cpe
      cpe = build_cpe(value: pdfVer, exp:"^([0-9.]+)", base:"cpe:/a:corel:pdf_fusion:");
      if(isnull(cpe))
        cpe = 'cpe:/a:corel:pdf_fusion';

      register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: appName,
                                               version: pdfVer,
                                               install: insPath,
                                               cpe: cpe,
                                               concluded: pdfVer));
    }
  }
}
