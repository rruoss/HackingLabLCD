###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_system_center_configmgr_detect_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft System Center Configuration Manager Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Microsoft System
  Center Configuration Manager.

The script logs in via smb, searches for Microsoft System Center Configuration
Manager in the registry and gets the version from 'DisplayVersion' string in
registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803023";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-12 09:47:47 +0530 (Wed, 12 Sep 2012)");
  script_name("Microsoft System Center Configuration Manager Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Microsoft System Center Configuration Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");


## Variable Initialization
keylist = "";
osArch = "";
key =  "";
item = "";
confmgrName = "";
confmgrPath = "";
confmgrVer = "";
smsVer = "";
smsPath = "";
cpe = "";

## Confirm target is Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}


## Check Processor Architecture
osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< osArch){
 keylist = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
else if("x64" >< osArch)
{
  keylist =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(keylist)){
  exit(0);
}

## Iterate over all registry paths
foreach key (keylist)
{
  ## Check the key existence
  if(registry_key_exists(key:key))
  {
    ## Iterate over all sub keys
    foreach item (registry_enum_keys(key:key))
    {
      ## Get the SCCM product name
      baseKey = key - "\Windows\CurrentVersion\Uninstall\";

      confmgrName = registry_get_sz(key:key + item, item:"DisplayName");

      ## Set KB item for Microsoft Systems Management Server 2003
      if("Microsoft Systems Management Server 2003" >< confmgrName )
      {
        newKey = baseKey + "\SMS\Setup";
        if(registry_key_exists(key: newKey))
        {
          smsVer = registry_get_sz(key: newKey, item:"Full UI Version");

          if(smsVer)
          {
            ## Set Version in KB
            set_kb_item(name:"MS/SMS/Version", value:smsVer);

            ## Get Install Location
            smsPath = registry_get_sz(key: newKey, item:"UI Installation Directory");
            if(! smsPath){
              smsPath = "Could not find the install Location from registry";
            }

            ## Set Path in KB
            set_kb_item(name:"MS/SMS/Path", value:smsPath);

            ## Build CPE
            cpe = build_cpe(value:smsVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:systems_management_server:");
            if(isnull(cpe))
              cpe = 'cpe:/a:microsoft:systems_management_server';

            register_product(cpe:cpe, location:smsPath, nvt:SCRIPT_OID);

            log_message(data: build_detection_report(app:confmgrName, version: smsVer,
                                                    install: smsPath, cpe:cpe, concluded:smsVer));
          }
        }
      }

      ## Set the KB item for Microsoft System Center Configuration Manager 2007
      if("Microsoft System Center Configuration Manager 2007" >< confmgrName &&
         !(confmgrName =~ "R2|R3"))
      {
        newKey = baseKey + "\ConfigMgr\Setup";
        if(registry_key_exists(key: newKey))
        {
          confmgrVer = registry_get_sz(key: newKey, item:"Full UI Version");

          if(confmgrVer)
          {
            ## Set Version in KB
            set_kb_item(name:"MS/ConfigMgr/Version", value:confmgrVer);

            ## Get Install Location
            confmgrPath = registry_get_sz(key: newKey, item:"UI Installation Directory");
            if(! confmgrPath){
              confmgrPath = "Could not find the install Location from registry";
            }

            ## Set Path in KB
            set_kb_item(name:"MS/ConfigMgr/Path", value:confmgrPath);

            ## Build CPE
            cpe = build_cpe(value:confmgrVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:system_center_configuration_manager:2007:");
            if(isnull(cpe))
              cpe = 'cpe:/a:microsoft:system_center_configuration_manager:2007';

            register_product(cpe:cpe, location:confmgrPath, nvt:SCRIPT_OID);

            log_message(data: build_detection_report(app:confmgrName, version: confmgrVer,
                                                     install: confmgrPath, cpe:cpe, concluded:confmgrVer));
          }
        }
      }

      ## Some Info about R2 and R3
      ## Base installtion Key will be there always and will set the above key
      ## InstallPath will be same as above and same can be used for R2/R3
      ## At time only one R2/R3 version can be installed not both.
      ## If R3 installed On R2, R2 key will be deleted from registry

      ## Setting KB versions for SCCM 2007 R2\R3 version
      if(confmgrName =~ "Microsoft System Center Configuration Manager 2007 [R3|R2]")
      {
        confmgrVer = registry_get_sz(key: key + item, item:"DisplayVersion");

        if(confmgrVer)
        {
          if(confmgrName =~ "R3"){
            ## Set Version in KB
            set_kb_item(name:"MS/ConfigMgr-R3/Version", value:confmgrVer);
          }

          if(confmgrName =~ "R2"){
            ## Set Version in KB
            set_kb_item(name:"MS/ConfigMgr-R2/Version", value:confmgrVer);
          }
        }
      }
    }
  }
}
