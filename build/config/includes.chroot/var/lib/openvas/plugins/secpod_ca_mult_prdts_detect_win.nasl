###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_mult_prdts_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# CA Multiple Products Version Detection (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-03-07
# Added HIPS Engine and HIPS Management Server Detection.
#
# Updated By:
# Rachana Shetty <srachana@secpod.com> on 2011-11-02
# Updated to detect CA Gateway Security
#
# Copyright:
# Copyright (c) 2009 SecPod, http//www.secpod.com
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
tag_summary = "This script detects the installed version of CA multiple
  products and sets the result in KB.";

if(description)
{
  script_id(900966);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:44:36 +0530 (Tue, 15 Nov 2011)");
  script_name("CA Multiple Products Version Detection (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the version of multiple CA products in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900966";
SCRIPT_DESC = "CA Multiple Products Version Detection (Win)";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ComputerAssociates")){
  exit(0);
}

# Check for eTrust EZ Antivirus
key = "SOFTWARE\ComputerAssociates\ProductInfoWSC";
ezavName = registry_get_sz(key:key, item:"DisplayName");
if("eTrust EZ Antivirus" >< ezavName)
{
  ezavVer = registry_get_sz(key:key, item:"ProductVersion");
  if(ezavVer){
    set_kb_item(name:"CA/eTrust-EZ-AV/Win/Ver", value:ezavVer);
    security_note(data:"CA eTrust EZ Antivirus version " + ezavVer +
                                              " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:ezavVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:ca:etrust_ez_antivirus:");
  }
}

key = "SOFTWARE\ComputerAssociates\eTrust Suite Personal\";
# Check for CA Anti-Virus
caavName = registry_get_sz(key:key + "\av", item:"Name");
if("Anti-Virus" >< caavName)
{
  caavVer = registry_get_sz(key:key + "\av", item:"Version");
  if(caavVer){
    set_kb_item(name:"CA/AV/Win/Ver", value:caavVer);
    security_note(data:"CA Antivirus version " + caavVer +
                                              " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:caavVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:ca:anti-virus:");
  }
}

# Check for CA Internet Security Suite
caissName = registry_get_sz(key:key + "\suite", item:"Name");
if("Internet Security Suite" >< caissName)
{
  caissVer = registry_get_sz(key:key + "\suite", item:"Version");
  if(caissVer){
    set_kb_item(name:"CA/ISS/Win/Ver", value:caissVer);
    security_note(data:"CA Internet Security version " + caissVer +
                                              " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:caissVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:ca:internet_security_suite");
  }
}

# Check for CA HIPS Engine
key = "SOFTWARE\CA\HIPSEngine";
cahipsVer = registry_get_sz(key:key, item:"Version");
if(cahipsVer){
  set_kb_item(name:"CA/HIPS/Engine/Win/Ver", value:cahipsVer);
  security_note(data:"CA HIPS Engine version " + cahipsVer +
                     " was detected on the host");
}

# Check for HIPS Management Server
if(registry_key_exists(key:"SOFTWARE\CA\HIPSManagementServer"))
{
  # Get HIPS Management Server Version From Registry
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      name = registry_get_sz(key:key + item, item:"DisplayName");
      if(eregmatch(pattern:"^CA HIPS Management Server", string:name))
      {
        hipsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(hipsVer != NULL)
        {
          set_kb_item(name:"CA/HIPS/Server/Win/Ver", value:hipsVer);
          security_note(data:"CA HIPS Management Server version " + hipsVer +
                             " was detected on the host");
        }
      }
    }
  }
}

# Check for CA Gateway Security
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    if("CA Gateway Security" >< registry_get_sz(key:key + item,
                                                item:"DisplayName"))
    {
      ## Get the install path for Gateway security
      cagsPath = registry_get_sz(key:key + item, item:"InstallLocation");
      cagsPath = cagsPath + "Bin";

      cagsVer = fetch_file_version(sysPath:cagsPath, file_name:"ManagerConsole.exe");
      if(cagsVer)
      {
        set_kb_item(name:"CA/Gateway-Security/Win/Ver", value:cagsVer);
        security_note(data:"CA Gateway Security version " + cagsVer +
                                                " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:cagsVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:ca:gateway_security:");
      }
    }
  }
}
