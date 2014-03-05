###################################################################
# OpenVAS Vulnerability Test
#
# Panda Antivirus Update Detect
#
# LSS-NVT-2010-037
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "Extracts date of the last update for Panda Antivirus software, from the 
  Titanium.ini file and stores it to KB.";

if(description)
{
  script_id(102048);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Panda Antivirus Update Detect");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
    script_summary("Gets update information for Panda Antivirus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Service detection");
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl","smb_reg_service_pack.nasl", "gb_panda_prdts_detect.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


#
# This script is tested on Panda Antivirus 2005 thru 2007
# For other versions of Panda software might not work due to non-existent titanium.ini file 
#

include("smb_nt.inc");
include("secpod_smb_func.inc");


port = get_kb_item("SMB/transport");
if (!port) port = 445;

#Detect if there is any Panda software installed
if(!registry_key_exists(key:"SOFTWARE\Panda Software")){
  exit(0);
}

#reading install directories from the registry
key = "SOFTWARE\Panda Software\";
foreach item (registry_enum_keys(key:key))
{
  ##  Check for the Internet Security
  if("Panda Internet Security" >< item)
    paths[0] = registry_get_sz(key:key + item, item:"DIR");

  ##  Check for the Global Protection
  if("Panda Global Protection" >< item)
    paths[1] = registry_get_sz(key:key + item, item:"DIR");

  ##  Check for the Antivirus
  if("Panda Antivirus" >< item)
    paths[2] = registry_get_sz(key:key + item, item:"DIR");   
}
  
for(i = 0; i < 3; i++){
   
  if(paths[i]){
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:paths[i]);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:paths[i]) + "\Titanium.ini";
    last_update = read_file(share:share, file:file, offset:0, count:1000);
    last_update = egrep(pattern:"^PavSigDate=(.*)$", string:last_update);
    last_update = ereg_replace(pattern:"^PavSigDate=(.*)$", replace:"\1", string:last_update);
    last_update = last_update - string("\r\n"); #removing the endline chars

    if(!last_update)
    {
      log_message(data:"Could not find last date of signature base update in file Titanium.ini");
      exit(-1);
    }

    #setting KB items
    if(i == 0)
      set_kb_item(name:"Panda/InternetSecurity/LastUpdate", value:last_update);
    if(i == 1)
      set_kb_item(name:"Panda/GlobalProtect/LastUpdate", value:last_update);
    if(i == 2)
      set_kb_item(name:"Panda/AntiVirus/LastUpdate", value:last_update);
  }
}
