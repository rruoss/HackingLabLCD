###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_internet_security_detect_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Comodo Internet Security Version Detection (Windows)
#
# Authors:
# Arun kallavi <karun@secpod.com>
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
tag_summary = "Detection of installed version of Comodo Internet Security.

The script logs in via smb, searches for Comodo Internet Security in the
registry and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803683";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-05 13:15:00 +0530 (Fri, 05 Jul 2013)");
  script_name("Comodo Internet Security Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Comodo Internet Security on Windows");
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

# Variable Initialization
key = "";
Name = "";
Path = "";
Ver = "";
cpe = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check if Comodo Internet Security is installed
key = "SOFTWARE\ComodoGroup\CDI\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  # Check for the Name
  Name = registry_get_sz(key:key + item, item:"Product Name");
  if("COMODO Internet Security" >< Name)
  {
    # Check for the install path
    Path = registry_get_sz(key:key + item, item:"InstallProductPath");
    if(!Path){
      Path = "Could not find the install Location";
    }

    # Check for the version
    Ver = registry_get_sz(key:key + item, item:"Product Version");
    if(Ver)
    {
      set_kb_item(name:"Comodo/InternetSecurity/Win/Ver", value:Ver);

      # build cpe
      cpe = build_cpe(value:Ver, exp:"^([0-9.]+)",
                      base:"cpe:/a:comodo:comodo_internet_security:");
      if(isnull(cpe))
        cpe = "cpe:/a:comodo:comodo_internet_security";

      register_product(cpe:cpe, location:Path, nvt:SCRIPT_OID);
      log_message(data: build_detection_report(app:"Comodo Internet Security",
                                          version:Ver, install:Path,
                                           cpe:cpe, concluded: Ver));
      exit(0);
    }
  }
}
