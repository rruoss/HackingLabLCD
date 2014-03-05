###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fsecure_prdts_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# F-Secure Multiple Products Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "The script detects the installed version of F-Seure Anti-Virus,
  Internet security and Internet GateKeeper and sets the version in KB.";

if(description)
{
  script_id(800357);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("F-Secure Multiple Products Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of F-Secure Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800357";
SCRIPT_DESC = "F-Secure Multiple Products Version Detection (Linux)";

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

# Set KB for F-Secure Linux Security and Anti-Virus Linux Client/Server Security
fsavPaths = find_file(file_name:"fsav", file_path:"/", useregex:TRUE,
                 regexpar:"$", sock:sock);

if(fsavPaths != NULL)
{
  foreach fsavBin (fsavPaths)
  {
    fsavVer = get_bin_version(full_prog_name:chomp(fsavBin), sock:sock,
                             version_argv:"--version",
                             ver_pattern:"F-Secure (Anti-Virus )?Linux (Client "+
                                         "|Server )?Security version ([0-9.]+)"+
                                         " build ([0-9]+)([^0-9.]|$)?");
    fsavName = fsavVer;
    if(fsavVer[3] != NULL)
    {
      if(fsavVer[4] != NULL){
         fsavVer = fsavVer[3] + "." + fsavVer[4];
      }
      else{
        fsavVer = fsavVer[3];
      }
      if(fsavName[0] =~ "Linux Security")
      {
        set_kb_item(name:"F-Sec/AV/LnxSec/Ver", value:fsavVer);
        security_note(data:"F-Secure Anti Virus version " + fsavVer + 
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:fsavVer, tmpExpr:"^([0-9]+\.[0-9]+)", tmpBase:"cpe:/a:f-secure:f-secure_linux_security:");

      }
      if(fsavName[0] =~ "Linux Client Security")
      {
        set_kb_item(name:"F-Sec/AV/LnxClntSec/Ver", value:fsavVer);
        security_note(data:"F-Secure Anti Virus Client Security version " + fsavVer +
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:fsavVer, tmpExpr:"^([0-9]+\.[0-9]+)", tmpBase:"cpe:/a:f-secure:f-secure_anti-virus_linux_client_security:");

      }
      if(fsavName[0] =~ "Linux Server Security")
      {
        set_kb_item(name:"F-Sec/AV/LnxSerSec/Ver", value:fsavVer);
        security_note(data:"F-Secure Server Security version " + fsavVer +
                           " was detected on the host"); 

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:fsavVer, tmpExpr:"^([0-9]+\.[0-9]+)", tmpBase:"cpe:/a:f-secure:f-secure_anti-virus_linux_server_security:");

      }
      break;
    }
  }
}

# Set KB for F-Secure Internet Gatekeeper
fsigkPaths = find_file(file_name:"Makefile", file_path:"/fsigk/", useregex:TRUE,
                       regexpar:"$", sock:sock);
if(fsigkPaths != NULL)
{
  foreach binPath (fsigkPaths)
  {
    fsigkVer = ssh_cmd(socket:sock, timeout:120, cmd:"egrep '^VERSION' " +
                                                     binPath);
    if(fsigkVer != NULL)
    {
      fsigkVer = eregmatch(pattern:"VERSION.*= ([0-9.]+)([^.0-9]|$)",
                           string:fsigkVer);

      if(fsigkVer[1] != NULL)
      {
        buildVer = ssh_cmd(socket:sock, timeout:120,
                           cmd:"egrep '^BUILD_NUMBER' " + binPath);

        buildVer = eregmatch(pattern:"BUILD_NUMBER.*= ([0-9]+)([^.0-9]|$)",
                             string:buildVer);

        if(buildVer[1] != NULL){
          fsigkVer = fsigkVer[1] + "." + buildVer[1];
        }
        else{
          fsigkVer = fsigkVer[1];
        }
        set_kb_item(name:"F-Sec/IntGatekeeper/Lnx/Ver", value:fsigkVer);
        security_note(data:"F-Secure Internet Gate Keeper version " + fsigkVer + 
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:fsigkVer, tmpExpr:"^([0-9]+\.[0-9]+)", tmpBase:"cpe:/a:f-secure:f-secure_internet_gatekeeper_for_linux:");

       }
      ssh_close_connection();
      exit(0);
    }
  }
}
ssh_close_connection();
