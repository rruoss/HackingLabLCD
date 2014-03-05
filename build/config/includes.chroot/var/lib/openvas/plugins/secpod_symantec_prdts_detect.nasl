###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_prdts_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Symantec Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Update By: Antu Sanadi <santu@secpod.com> on 2010-02-25
# Updated to detect and set KB for EndPoint Protection IM Manager
#
# Update By: Sooraj KS <kssooraj@secpod.com> on 2011-02-01
# Updated to detect Symantec AntiVirus Corporate Edition
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-03-03
# Updated to detect Symantec Norton AntiVirus and according to CR-57
# On 2012-11-23 to detect SEPSBE
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
tag_summary = "Detection of installed version of Symantec Product(s)

The script logs in via smb, searches for Symantec Product(s) in the registry
and gets the version from registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900332";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_name("Symantec Product(s) Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detection of installed version of Symantec Product(s)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check for Symantec Endpoint Protection
key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SEPM";

if(registry_key_exists(key:key))
{
  # Setting KB for Endpoint Protection
  nisVer = registry_get_sz(key:key, item:"Version");
  if(nisVer)
  {
    set_kb_item(name:"Symantec/Endpoint/Protection", value:nisVer);

    ## Get Install Location
    nisPath = registry_get_sz(key: key + item, item:"TargetDir");
    if(! nisPath){
      nisPath = "Could not find the install Location from registry";
    }

    ## For Symantec Endpoint Protection Small Business Edition
    ## Chekc product Type sepsb (Symantec Endpoint Protection Small Businees)

    nisType = registry_get_sz(key:key, item:"ProductType");
    if(nisType && "sepsb" >< nisType)
    {
      ## Set kb for product type
      set_kb_item(name:"Symantec/SEP/SmallBusiness", value:nisType);

      ## Buidl CPE
      cpe = build_cpe(value:nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:endpoint_protection:"
                                     + nisVer + ":small_business");
    }

    else{
      ## Build CPE
      cpe = build_cpe(value: nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:endpoint_protection:");
    }

    if(isnull(cpe))
       cpe = 'cpe:/a:symantec:endpoint_protection';

    register_product(cpe:cpe, location:nisPath, nvt:SCRIPT_OID);

    log_message(data: build_detection_report(app: symantecName, version: nisVer,
                                             install: nisPath, cpe:cpe, concluded:nisVer));
  }
}


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  symantecName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Symantec pcAnywhere" >< symantecName)
  {
    pcawVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pcawVer){
      set_kb_item(name:"Symantec/pcAnywhere/Ver", value:pcawVer);

      ## Get Install Location
      pcawPath = registry_get_sz(key: key + item, item:"InstallLocation");
      if(! pcawPath){
        pcawPath = "Could not find the install Location from registry";
      }

      ## Build CPE
      cpe = build_cpe(value: pcawVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:pcanywhere:");
      if(isnull(cpe))
         cpe = 'cpe:/a:symantec:pcanywhere';

      register_product(cpe:cpe, location:pcawPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: pcawVer,
                                               install: pcawPath, cpe:cpe, concluded:pcawVer));

    }
  }

  if("Norton Internet Security" >< symantecName)
  {
    nisVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(nisVer){
      set_kb_item(name:"Norton/InetSec/Ver", value:nisVer);

      ## Get Install Location
      nisPath = registry_get_sz(key: key + item, item:"InstallLocation");
      if(! nisPath){
        nisPath = "Could not find the install Location from registry";
      }

      ## Build CPE
      cpe = build_cpe(value: nisVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_internet_security:");
      if(isnull(cpe))
         cpe = 'cpe:/a:symantec:norton_internet_security';

      register_product(cpe:cpe, location:nisPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: nisVer,
                                               install: nisPath, cpe:cpe, concluded:nisVer));

    }
  }

  # Setting KB for IMManager
  if("IMManager" >< symantecName)
  {
    imPath = registry_get_sz(key:key + item, item:"InstallSource");
    if(!isnull(imPath))
    {
      imPath = imPath - "\temp" + "IMLogicAdminService.exe";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:imPath);
      file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:imPath);

      imVer = GetVer(file:file, share:share);
      if(!isnull(imVer))
      {
        set_kb_item(name:"Symantec/IM/Manager", value:imVer);

        ## Build CPE
        cpe = build_cpe(value: imVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:im_manager:");
      if(isnull(cpe))
         cpe = 'cpe:/a:symantec:im_manager';

      register_product(cpe:cpe, location:imPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: imVer,
                                               install: imPath, cpe:cpe, concluded:imVer));
      }
    }
  }

  ## Symantec AntiVirus Corporate Edition
  if("Symantec AntiVirus" >< symantecName)
  {
    savceVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(savceVer)
    {
      set_kb_item(name:"Symantec/SAVCE/Ver", value:savceVer);

      ## Get Install Location
      savcePath = registry_get_sz(key: key + item, item:"InstallLocation");
      if(! savcePath){
        savcePath = "Could not find the install Location from registry";
      }

      ## Build CPE
      cpe = build_cpe(value: savceVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:antivirus:");
      if(isnull(cpe))
         cpe = 'cpe:/a:symantec:antivirus';

      register_product(cpe:cpe, location: savcePath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: savceVer,
                                               install: savcePath, cpe:cpe, concluded:savceVer));

    }
  }

 ## Symantec Norton AntiVirus
 if("Norton AntiVirus" >< symantecName)
  {
    navVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(navVer)
    {
      set_kb_item(name:"Symantec/Norton-AV/Ver", value:navVer);

      ## Get Install Location
      navPath = registry_get_sz(key: key + item, item:"InstallLocation");
      if(! navPath){
        navPath = "Could not find the install Location from registry";
      }

     ## Build CPE
     cpe = build_cpe(value:navVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:norton_antivirus:");
     if(isnull(cpe))
        cpe = 'cpe:/a:symantec:norton_antivirus';

      register_product(cpe:cpe, location:navPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: navVer,
                                                install: navPath, cpe:cpe, concluded:navVer));
    }
  }

  ## Symantec Enterprise Security Manager (ESM)
  if("Enterprise Security Manager" >< symantecName)
  {
    esmVer = registry_get_sz(key:key + item, item:"DisplayVersion"); 
    if(esmVer)
    {
      set_kb_item(name:"Symantec/ESM/Ver", value:esmVer);
      set_kb_item(name:"Symantec/ESM/Component", value:symantecName);

      ## Get Install Location 
      esmPath = registry_get_sz(key: key + item, item:"InstallLocation");
      if(! esmPath){
        esmPath = "Could not find the install Location from registry";
      }

      set_kb_item(name:"Symantec/ESM/Path", value:esmPath);
      ## Build CPE
      cpe = build_cpe(value:esmVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:enterprise_security_manager:");
      if(isnull(cpe))
        cpe = 'cpe:/a:symantec:enterprise_security_manager';

      register_product(cpe:cpe, location:esmPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: symantecName, version: esmVer,
                                                install: esmPath, cpe:cpe, concluded:esmVer));
    }
  }
}
