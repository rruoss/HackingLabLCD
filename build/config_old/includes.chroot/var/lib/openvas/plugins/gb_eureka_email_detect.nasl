##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eureka_email_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Eureka Email Version Detection
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
tag_summary = "This script detects the installed version of Eureka Email and
  sets the result in KB.";

if(description)
{
  script_id(801040);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Eureka Email Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Eureka Email in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801040";
SCRIPT_DESC = "Eureka Email Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
   exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  eeName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Eureka Email" >< eeName)
  {
    eePath = registry_get_sz(key:key + item, item:"Inno Setup: App Path");
    if(eePath)
    {
      eePath += "\Eureka Email.EXE";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:eePath);
      file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:eePath);

      eeVer = GetVer(file:file, share:share);
      if(eeVer != NULL)
      {
        set_kb_item(name:"EurekaEmail/Ver", value:eeVer);
        security_note(data:"Eureka Email version " + eeVer + " was detected on the host"); 
  
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:eeVer, exp:"^([0-9.]+)", base:"cpe:/a:eureka-email:eureka_email:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}
