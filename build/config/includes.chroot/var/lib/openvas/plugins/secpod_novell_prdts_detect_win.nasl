###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_prdts_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Novell Multiple Products Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Modified by: Nikita MR (rnikita@secpod.com)
# Date: 24th July 2009
# Changes: Modified the kb name to indicate windows version.
#
# Modified by: Nikita MR (rnikita@secpod.com)
# Date: 09th Nov 2009
# Changes: Added check for Novell Groupwise client.
#
# Updated by: Madhuri D  <dmadhuri@secpod.com> on 2010-08-13
#  Modified to detect recent versions.
#
# Update By: Antu Sanadi <santu@secpod.com> on 2011-04-12
#  Updated to detect Novell File Reporter.
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
tag_summary = "This script detects the installed version of Novell Products
  and sets the result in KB.";

if(description)
{
  script_id(900340);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Novell Multiple Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of Novell Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900340";
SCRIPT_DESC = "Novell Multiple Products Version Detection";

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

# Set KB for Novell eDirectory (NDSD)
if(registry_key_exists(key:"SOFTWARE\Novell\NDS"))
{
  eDirName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\NDSonNT", item:"DisplayName");
  if("eDirectory" >< eDirName)
  {
    eDirVer = eregmatch(pattern:"([0-9]\.[0-9.]+).?(SP[0-9])?", string:eDirName);
    if(eDirVer[1] != NULL && eDirVer[2] != NULL){
      eDirVer = eDirVer[1] + "." + eDirVer[2];
    }
    else{
      eDirVer = eDirVer[1];
    }
    if(eDirVer){
      set_kb_item(name:"Novell/eDir/Win/Ver", value:eDirVer);
      security_note(data:"Novell eDirectory version " + eDirVer +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:eDirVer, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:novell:edirectory:");

    }
  }
}

# Set KB for Novell iPrint
if(registry_key_exists(key:"SOFTWARE\Novell-iPrint"))
{
  ver = registry_get_sz(key:"SOFTWARE\Novell-iPrint", item:"Current Version");
  if(ver)
  {
    iprintVer = eregmatch(pattern:"([0-9.]+)" , string:ver);
    iprintVer = iprintVer[1];
  }
  else
  {
    iprintName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                    "\Uninstall\Novell iPrint Client",
                                item:"DisplayName");
    if("iPrint" >< iprintName)
    {
      iprintVer = eregmatch(pattern:"v([0-9.]+)", string:iprintName);
      if(iprintVer[1]){
          iprintVer = iprintVer[1];
      }
    }
  }
}

if(iprintVer){
    set_kb_item(name:"Novell/iPrint/Ver", value:iprintVer);
    security_note(data:"Novell iPrint version " + iprintVer +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:iprintVer, tmpExpr:"^([0-9]\.[0-9]+)", tmpBase:"cpe:/a:novell:iprint:");

}

# Set KB for Novell Client
if(registry_key_exists(key:"SOFTWARE\Novell"))
{
  clientVer = registry_get_sz(key:"SOFTWARE\Novell\NetWareWorkstation" +
                                  "\CurrentVersion", item:"ProductName");
  if("Novell Client" >< clientVer)
  {
    clientVer = eregmatch(pattern:"([0-9]\.[0-9.]+).?(SP[0-9]+)?", string:clientVer);
    if(clientVer[1] != NULL && clientVer[2] != NULL){
      clientVer = clientVer[1] + "." + clientVer[2];
    }
    else if(clientVer[1] =~ "[0-9]+"){
      clientVer = clientVer[1];
    }
  }
  else{
    clientVer = registry_get_sz(key:"SOFTWARE\Novell", item:"CurrentVersion");
  }

  if(clientVer){
    set_kb_item(name:"Novell/Client/Ver", value:clientVer);
    security_note(data:"Novell Client version " + clientVer +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:clientVer, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:novell:client:");

  }
}

# Set KB for Novell NetIdentity
if(registry_key_exists(key:"SOFTWARE\Novell\NetIdentity"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(registry_key_exists(key:key))
  {
  foreach item (registry_enum_keys(key:key))
  {
    netidName = registry_get_sz(key:key + item, item:"DisplayName");

    if("NetIdentity" >< netidName)
    {
      netidVer = eregmatch(pattern:"([0-9]\.[0-9.]+)", string:netidName);

      if(netidVer[1] != NULL)
      {
        set_kb_item(name:"Novell/NetIdentity/Ver", value:netidVer[1]);
        security_note(data:"Novell NetIdentity version " + netidVer[1] +
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:netidVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:novell:netidentity_client:");


        buildVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(!buildVer)
        {
          buildVer = registry_get_sz(key:"SOFTWARE\Novell\NetIdentity",
                                     item:"Version");
        }
        if(buildVer){
          set_kb_item(name:"Novell/NetIdentity/Build/Ver", value:buildVer);
        }
      }
    }
  }
  }
}

# Set kb for Novell Groupwise Client
if(registry_key_exists(key:"SOFTWARE\Novell\GroupWise"))
{
  gcPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                               "\App Paths\GrpWise.exe", item:"Path");
  if(gcPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:gcPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:gcPath +
                                                             "\GrpWise.exe");
    gcVer = GetVer(file:file, share:share);
    if(gcVer != NULL){
      set_kb_item(name:"Novell/Groupwise/Client/Win/Ver", value:gcVer);
      security_note(data:"Novell Groupwise Client version " + gcVer +
                         " running at location " + gcPath +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:gcVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:novell:groupwise:");

    }
  }
}

# Set KB for Novell File Reporter
if(registry_key_exists(key:"SOFTWARE\Novell\File Reporter"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(!registry_key_exists(key:key)){
   exit(0);
  }
  foreach item (registry_enum_keys(key:key))
  {
    nfrName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Novell File Reporter" >< nfrName)
    {
      nfrVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(nfrVer != NULL)
      {
        set_kb_item(name:"Novell/FileReporter/Ver", value:nfrVer);
        security_note(data:"Novell File Reporter version " + nfrVer +
                           " was detected on the host");
      }
    }
  }
}
