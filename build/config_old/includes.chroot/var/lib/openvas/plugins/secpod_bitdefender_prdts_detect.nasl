###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitdefender_prdts_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# BitDefender Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script retrieves the installed version of BitDefender
  Product(s) and sets the result in KB.";

if(description)
{
  script_id(900326);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("BitDefender Product(s) Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets version in KB for BitDefender Product(s)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900326";
SCRIPT_DESC = "BitDefender Product(s) Version Detection";

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

bitKey = "SOFTWARE\BitDefender\About";
bitName = registry_get_sz(key:bitKey, item:"ProductName");

if(bitName)
{
  if("BitDefender Internet Security" >< bitName)
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");
    if(bitVer == NULL)
    {
      bitVer = registry_get_sz(key:"SOFTWARE\BitDefender\BitDefender Desktop" +
                                   "\Maintenance\InternetSecurity",
                               item:"ProductVersion");
    }
    if(bitVer){
      set_kb_item(name:"BitDefender/InetSec/Ver", value:bitVer);
      security_note(data:"BitDefender Internet Security version " + bitVer +
                                                 " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:bitVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:bitdefender:internet_security:");

    }
  }

  if("BitDefender Antivirus" >< bitName)
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");
    if(bitVer == NULL)
    {
      bitVer = registry_get_sz(key:"SOFTWARE\BitDefender\BitDefender Desktop" +
                                   "\Maintenance\Antivirus",
                               item:"ProductVersion");
    }
    if(bitVer){
      set_kb_item(name:"BitDefender/AV/Ver", value:bitVer);
      security_note(data:"BitDefender Antivirus version " + bitVer + 
                                                 " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:bitVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:bitdefender:bitdefender_antivirus:");

    }
  }
}
