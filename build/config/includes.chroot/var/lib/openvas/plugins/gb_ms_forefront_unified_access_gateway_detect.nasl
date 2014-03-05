###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_forefront_unified_access_gateway_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Forefront Unified Access Gateway (UAG) Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Microsoft Forefront
                      Unified Access Gateway (UAG).

The script logs in via smb, searches for Microsoft Forefront Unified Access
Gateway (UAG) in the registry and gets the version from 'Version' string in
registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802746";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-13 10:46:45 +0530 (Fri, 13 Apr 2012)");
  script_name("Microsoft Forefront Unified Access Gateway (UAG) Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of MS Forefront Unified Access Gateway");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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
uagName = "";
uagVer = "";
cpe = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  uagName = registry_get_sz(key:key + item, item:"DisplayName");

  if(!uagName){
    continue;
  }

  ## Confirm the application
  if("Microsoft Forefront Unified Access Gateway" >< uagName)
  {
    ## Get version from registry
    uagVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(uagVer)
    {
      ## Set the KB item
      set_kb_item(name:"MS/Forefront/UAG/Ver", value:uagVer);
      cpe = build_cpe(value:uagVer, exp:"^([0-9.]+)",
                    base:"cpe:/a:microsoft:forefront_unified_access_gateway:");

      insPath= 'Could not determine InstallLocation from Registry\n';
      if(cpe)
        register_product(cpe:cpe, location:insPath, nvt:SCRIPT_OID);

      log_message(data:'Detected MS Forefront Unified Access Gateway version: ' + uagVer +
                      '\nLocation: ' + insPath +
                      '\nCPE: '+ cpe +
                      '\n\nConcluded from version identification result:\n' +
                      'MS ForefrontUnified Access Gateway ' + uagVer);

    }
  }
}
