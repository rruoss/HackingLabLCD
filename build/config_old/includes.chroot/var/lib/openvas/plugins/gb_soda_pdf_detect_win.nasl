###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soda_pdf_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Soda PDF Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803750";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-03 10:35:37 +0530 (Tue, 03 Sep 2013)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Soda PDF Detection (Windows)");

  tag_summary =
"Detection of installed version of Soda PDF.

The script logs in via smb, searches for Soda PDF and gets the version
from 'DisplayVersion' string in registry";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check for the Soda PDF installation and set the version in KB for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable Initialization
key = "";
sodaVer= "";
insloc= "";
sodaName = "";

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sodaName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Soda PDF" >< sodaName)
  {
    ## Get the Installed Path
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      exit(0);
    }

    ## Get RSA Authentication Agent Version
    sodaVer  = fetch_file_version(sysPath:insloc, file_name:"PDFServerEngine.exe");
    if(sodaVer)
    {
      set_kb_item(name:"Soda/PDF/Ver/Win", value:sodaVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:sodaVer, exp:"^([0-9.]+)", base:"cpe:/a:soda:soda_pdf:");
      if(isnull(cpe))
        cpe = "cpe:/a:soda:soda_pdf";

      register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: "Soda PDF",
                                               version: sodaVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: sodaVer));
    }
  }
}
