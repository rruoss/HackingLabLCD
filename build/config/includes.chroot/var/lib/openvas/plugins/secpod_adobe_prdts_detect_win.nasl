###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Adobe Products Version Detection (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated by: Madhuri D <dmadhuri@secpod.com> on 2011-05-25
# - Updated script to detect Adobe Audition
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2012-01-13
# - Updated to detect for 64 bit platform also.
# - Updated according to CR 57.
# - Updated to avoid setting same version multiple times.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to new style script_tags.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900319";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Adobe Products Version Detection (Win)");

  tag_summary =
"Detection of installed version of Adobe Products.

The script logs in via smb, searches for Adobe Products in the registry
and gets the version from 'DisplayVersion' string in registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set KB for the version of Adobe Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variable Initialization
checkdupAcrbt = "";
checkdupRdr = "";
checkdupAud = "";
acrobatVer = "";
readerVer = "";
adkeylist = "";
adobeName = "";
audName = "";
insPath = "";
keylist = "";
osArch = "";
syskey = "";
item = "";
key =  "";
cpe = "";

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
}

## Confirm target is Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check Processor Architecture
syskey = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if(!registry_key_exists(key:syskey)) {
  exit(0);
}

osArch = registry_get_sz(key:syskey, item:"PROCESSOR_ARCHITECTURE");
if(!osArch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< osArch){
 keylist = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
else if("64" >< osArch)
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
      ## Get the adobe product name
      adobeName = registry_get_sz(key:key + item, item:"DisplayName");

      ##  Confirm for Adobe Acrobat
      if(egrep(string:adobeName, pattern:"^(Adobe Acrobat)"))
      {
        ## Get the version
        acrobatVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(acrobatVer != NULL && insPath)
        {
          ## Check if version is already set
          if (acrobatVer + ", " >< checkdupAcrbt){
            continue;
          }

          checkdupAcrbt  += acrobatVer + ", ";

          ## Set version for 64 bit Adobe Acrobat on 64 bit OS
          if( "x64" >< osArch && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Acrobat64/Win/Ver", value:acrobatVer);
          }
          else
          {
            ##  Set the version for 32 bit Adobe Acrobat on 32 bit OS
            ##  Set the version for 32 bit Adobe Acrobat on 64 bit OS
            set_kb_item(name:"Adobe/Acrobat/Win/Ver", value:acrobatVer);
          }

          ## Build CPE
          cpe = build_cpe(value:acrobatVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:acrobat";

          ## Register Product and Build Report
          build_report(app: adobeName, ver: acrobatVer, cpe: cpe, insloc: insPath);
        }
      }

      ## Confirm for Adobe Reader
      else if(egrep(string:adobeName, pattern:"^(Adobe Reader)"))
      {
        readerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(readerVer != NULL && insPath)
        {

          ## Check if version is already set
          if (readerVer + ", " >< checkdupRdr){
            continue;
          }

          checkdupRdr += readerVer + ", ";

          # set version for 64 bit Adobe Acrobat on 64 bit OS
          if( "x64" >< os64bit && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Reader64/Win/Ver", value:readerVer);
          }
          else
          {
            ##  Set the version for 32 bit Adobe Reader on 32 bit OS
            ##  Set the version for 32 bit Adobe Reader on 64 bit OS
            set_kb_item(name:"Adobe/Reader/Win/Ver", value:readerVer);
          }

          ## Build CPE
          cpe = build_cpe(value:readerVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_reader:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:acrobat_reader";

          ## Register Product and Build Report
          build_report(app: adobeName, ver: readerVer, cpe: cpe, insloc: insPath);
        }
      }
    }
  }
}


## Adobe Audition
## Check for 32 bit platform
if("x86" >< osArch){
adkeylist = make_list("SOFTWARE\Adobe\Audition\");
}

## Check for 64 bit platform
else if("64" >< osArch)
{
  adkeylist =  make_list("SOFTWARE\Adobe\Audition\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Iterate over all registry paths
foreach key (adkeylist)
{
  ## Check the key existence
  if(registry_key_exists(key:key))
  {
    ## Iterate over all sub keys
    foreach item (registry_enum_keys(key:key))
    {
      audName = registry_get_sz(key:key + item, item:"DisplayName");

      ## Confirm Adobe Audition
      if(egrep(string:audName, pattern:"^(Adobe Audition)"))
      {
        ## Check for the version
        audVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(audVer != NULL && insPath)
        {
          ## Check if version is already set
          if (audVer + ", " >< checkdupAud){
            continue;
          }

          checkdupAud  += audVer + ", ";

          ## set version for 64 bit Adobe Audition on 64 bit OS
          if( "x64" >< os64bit && "Wow6432Node" >!< key){
            set_kb_item(name:"Adobe/Audition64/Win/Ver", value:audVer);
          }
          else
          {
            ##  Set the version for 32 bit Adobe Audition on 32 bit OS
            ##  Set the version for 32 bit Adobe Audition on 64 bit OS
            set_kb_item(name:"Adobe/Audition/Win/Ver", value:audVer);
          }

          ## Build CPE
          cpe = build_cpe(value:audVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:audition:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:audition";

          ## Register Product and Build Report
          build_report(app: audName, ver: audVer, cpe: cpe, insloc: insPath);
        }
      }
    }
  }
}
