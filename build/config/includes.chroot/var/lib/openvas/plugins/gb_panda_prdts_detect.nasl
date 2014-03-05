##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_prdts_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Panda Products Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed Panda Products and saves the
  version in KB.";

if(description)
{
  script_id(801079);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Panda Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Panda Products in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801079";
SCRIPT_DESC = "Panda Products Version Detection";

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

if(!registry_key_exists(key:"SOFTWARE\Panda Software")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  avName = registry_get_sz(key:key + item, item:"DisplayName");
  ##  Check for the Internet Security
  if("Panda Internet Security" >< avName)
  {
    pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pandaVer != NULL)
    {
     set_kb_item(name:"Panda/InternetSecurity/Ver", value:pandaVer);
     security_note(data:"Panda Internet Security version " + pandaVer +
                         " was detected on the host");

     ## build cpe and store it as host_detail
     register_cpe(tmpVers:pandaVer, tmpExpr:"^(15\.0)", tmpBase:"cpe:/a:pandasecurity:panda_internet_security:2010::pro");
    }
  }

  ##  Check for the Global Protection
  if("Panda Global Protection" >< avName)
  {
    pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pandaVer != NULL)
    {
      set_kb_item(name:"Panda/GlobalProtection/Ver", value:pandaVer);
      security_note(data:"Panda Global Protection version " + pandaVer +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:pandaVer, tmpExpr:"^(3\.0)", tmpBase:"cpe:/a:pandasecurity:panda_global_protection:2010");
    }
  }

  ##  Check for the Antivirus
  if("Panda Antivirus" >< avName)
  {
    pandaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pandaVer != NULL)
    {
      set_kb_item(name:"Panda/Antivirus/Ver", value:pandaVer);
      security_note(data:"Panda Antivirus version " + pandaVer +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:pandaVer, tmpExpr:"^(9\.0)", tmpBase:"cpe:/a:pandasecurity:panda_antivirus::2010::pro");
    }
  }
}
