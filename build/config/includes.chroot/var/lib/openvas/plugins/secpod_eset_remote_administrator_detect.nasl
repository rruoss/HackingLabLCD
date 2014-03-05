###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_eset_remote_administrator_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# ESET Remote Administrator Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of ESET Remote
  Administrator and saves the version in KB.";

if(description)
{
  script_id(900508);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ESET Remote Administrator Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("General");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_summary("Set Version of ESET Remote Administrator in KB");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900508";
SCRIPT_DESC = "ESET Remote Administrator Version Detection";

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

if(registry_key_exists(key:"SOFTWARE\ESET\ESET Remote Administrator\Console"))
{
  consoleVer = registry_get_sz(key:"SOFTWARE\ESET\ESET Remote Administrator" +
                                   "\Console\CurrentVersion\Info",
                               item:"ProductVersion");
  if(consoleVer != NULL){
    set_kb_item(name:"ESET/RemoteAdmin/Console/Ver", value:consoleVer);
    security_note(data:"ESET Remote Administrator Console version " + 
                                   consoleVer + " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:consoleVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:eset:remote_administrator:");

  }
}

if(registry_key_exists(key:"SOFTWARE\ESET\ESET Remote Administrator\Server"))
{
  servVer = registry_get_sz(key:"SOFTWARE\ESET\ESET Remote Administrator" +
                                "\Server\CurrentVersion\Info",
                            item:"ProductVersion");
  if(servVer != NULL){
    set_kb_item(name:"ESET/RemoteAdmin/Server/Ver", value:servVer);
    security_note(data:"ESET Remote Administrator Server version " + 
                                   servVer + " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:servVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:eset:remote_administrator:");

  }

}

