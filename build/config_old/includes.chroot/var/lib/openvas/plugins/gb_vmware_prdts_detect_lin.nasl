###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# VMware products version detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2011-06-09
#  -Updated null check
#  -Updated to set version for Vmware ESX
#  -updated to set version for Vmware player
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script retrieves all VMware Products version and saves those
  in KB.";

if(description)
{
  script_id(800001);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("VMware products version detection (Linux)");
  desc ="
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Get/Set the versions of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800001";
SCRIPT_DESC = "VMware products version detection (Linux)";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

version = ssh_cmd(socket:sock, cmd:"vmware -v", timeout:120);
if("VMware GSX Server" >< version)
{
  gsxVer = ereg_replace(string:version, replace:"\1",
                        pattern:".*VMware GSX Server ([0-9].*) build.*");

  if(!isnull(gsxVer)){
     set_kb_item(name:"VMware/GSX-Server/Linux/Ver", value:gsxVer);

     ## build cpe and store it as host_detail
     register_cpe(tmpVers:gsxVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:vmware:gsx_server:");

  }

  gsxBuild = ereg_replace(string:version, replace:"\1",
                          pattern:".*VMware GSX Server [0-9].* build-([0-9]+).*");
  if(!isnull(gsxBuild)){
    set_kb_item(name:"VMware/GSX-Server/Linux/Build", value:chomp(gsxBuild));
  }

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
  security_note(data:"VMware GSX Server version " + gsxVer +
                                                 " was detected on the host");

  ssh_close_connection();
  exit(0);
}

else if("VMware Workstation" >< version)
{
  wrkstnVer = ereg_replace(string:version, replace:"\1",
                           pattern:".*VMware Workstation ([0-9].*) build.*");
  if(!isnull(wrkstnVer)){
    set_kb_item(name:"VMware/Workstation/Linux/Ver", value:wrkstnVer);

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:wrkstnVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:vmware:workstation:");

  }

  wrkstnBuild = ereg_replace(string:version, replace:"\1",
                             pattern:".*VMware Workstation [0-9].* build-([0-9]+).*");
  if(!isnull(wrkstnBuild)){
    set_kb_item(name:"VMware/Workstation/Linux/Build", value:chomp(wrkstnBuild));
  }

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
  security_note(data:"VMware Workstation version " + wrkstnVer +
                                                 " was detected on the host");

  ssh_close_connection();
  exit(0);
}

else if("VMware Server" >< version)
{
  svrVer = ereg_replace(string:version, replace:"\1",
                        pattern:".*VMware Server ([0-9].*) build.*");
  if(!isnull(svrVer)){
    set_kb_item(name:"VMware/Server/Linux/Ver", value:svrVer);

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:svrVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:vmware:server:");

  }

  svrBuild = ereg_replace(string:version, replace:"\1",
                          pattern:".*VMware Server [0-9].* build-([0-9]+).*");
  if(!isnull(svrBuild)){
    set_kb_item(name:"VMware/Server/Linux/Build", value:chomp(svrBuild));
  }

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
  security_note(data:"VMware Server version " + svrVer +
                                       " was detected on the host");

  ssh_close_connection();
  exit(0);
}

## Set VMware ESX version
else if("VMware ESX" >< version)
{
  svrVer = ereg_replace(string:version, replace:"\1",
                        pattern:".*VMware ESX ([0-9].*) build.*");
  if(!isnull(svrVer)){
    set_kb_item(name:"VMware/Esx/Linux/Ver", value:svrVer);
  }
  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
  security_note(data:"VMware ESX version " + svrVer +
                                      " was detected on the host");

  ssh_close_connection();
  exit(0);
}

## Set Vmware player version
path = ssh_cmd(socket:sock, cmd:"which vmplayer", timeout:120);
if(!isnull(path))
{
  catRes  = ssh_cmd(socket:sock, timeout:120, cmd:"cat /etc/vmware/config");
  if(!isnull(catRes))
  {
    vmpVer = eregmatch(pattern:'player.product.version = "([0-9.]+)', string:catRes);
    if(vmpVer[1] != NULL)
    {
      set_kb_item(name:"VMware/Player/Linux/Ver", value:vmpVer[1]);
      set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
      security_note(data:"VMware Player version " + vmpVer[1]+
                                             " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:vmpVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:vmware:player:");

    }
  }
}
ssh_close_connection();
