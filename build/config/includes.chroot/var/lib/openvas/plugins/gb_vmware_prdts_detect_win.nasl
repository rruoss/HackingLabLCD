###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_detect_win.nasl 42 2013-11-04 19:41:32Z jan $
#
# VMware products version detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_summary = "This script retrieves all VMWare Products version from registry and
  saves those in KB.";

if(description)
{
  script_id(800000);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("VMWare products version detection (Windows)");
  desc ="
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Get/Set the versions of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800000";
SCRIPT_DESC = "VMWare products version detection (Windows)";

VMWARE_LIST = make_list("^([0-9.]+([a-z0-9]+)?)", "cpe:/a:vmware:ace:",
                        "^([0-9.]+)", "cpe:/a:vmware:player:",        # Player
                        "^([0-9.]+)", "cpe:/a:vmware:server:",        # Server
                        "^([0-9.]+)", "cpe:/a:vmware:workstation:",   # Workstation
                        "^([0-9.]+)", "cpe:/a:vmware:ace:",           # ACE
                        "^([0-9.]+)", "cpe:/a:vmware:ace:");          # ACE\Dormant
VMWARE_MAX = max_index(VMWARE_LIST);

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){ #Ensure it is Windows
  exit(0);
}

vmVer = 0;

# Check for latest version of VMware ACE product
vmKey = "SOFTWARE\VMware, Inc.\VMware ACE\Dormant";
if(registry_key_exists(key:vmKey))
{
  uninstall = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  keys = registry_enum_keys(key:uninstall);

  if(keys == NULL){
    exit(0);
  }

  foreach key (keys)
  {
    vmace = registry_get_sz(key:uninstall + key, item:"DisplayName");
    if("VMware ACE Manager" >< vmace)
    {
      vmVer = registry_get_sz(key:uninstall + key, item:"DisplayVersion");
      break;
    }
  }
}

if(!vmVer)
{
  # Check for all 5 VMware Products
  vmwarePrdts = make_list("SOFTWARE\VMware, Inc.\VMware GSX Server",
                          "SOFTWARE\VMware, Inc.\VMware Workstation",
                          "SOFTWARE\VMware, Inc.\VMware Player",
                          "SOFTWARE\VMWare, Inc.\VMWare Server",
                          "SOFTWARE\VMware, Inc.\VMware ACE");

  foreach vmKey (vmwarePrdts)
  {
    vmwareCode = registry_get_sz(key:vmKey, item:"ProductCode");
    if(vmwareCode)
    {
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + vmwareCode;
      vmVer = registry_get_sz(key:key, item:"DisplayVersion");
      vmPath = registry_get_sz(key:vmKey, item:"InstallPath");

      break;
    }
  }
}

if(vmVer != NULL)
{
  vmware = split(vmVer, sep:".", keep:0);
  vmwareVer = vmware[0] + "." + vmware[1] + "." + vmware[2];

  if(vmPath)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vmPath);
    file1 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:vmPath + "vmware.exe");
    file2 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", 
                         string:vmPath + "vmplayer.exe");
    file3 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:vmPath + "vmware-authd.exe");
  
    soc = open_sock_tcp(port);
    if(!soc){
      exit(0);
    } 
  
    r = smb_session_request(soc:soc, remote:name);
    if(!r){
      close(soc);
      exit(0);
    } 

    prot = smb_neg_prot(soc:soc);
    if(!prot){
      close(soc);
      exit(0);
    }

    r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                          prot:prot);
    if(!r){
      close(soc);
      exit(0);
    }

    uid = session_extract_uid(reply:r);
    r = smb_tconx(soc:soc, name:name, uid:uid, share:share);

    tid = tconx_extract_tid(reply:r);
    if(!tid){
      close(soc);
      exit(0);
    }

    fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file1);
    if(!fid)
    {
      fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file2);
      if(!fid)
      {
        fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file3);
        if(!fid)
        {
          close(soc);
          exit(0);
        }
      }
    }

    vmwareBuild = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:290000,
                             verstr:"build-");
    close(soc);
  }

  # Check for strange vmware workstation versions
  if(vmwareBuild == "19175" && vmwareVer == "5.5.0"){
    vmwareVer = "5.5.1";
  }

  product = ereg_replace(pattern:"SOFTWARE\\VMWare, Inc.\\VMWare (.*)",
                         string:vmKey, replace:"\1", icase:TRUE);

  # Set KB's for GSX Server, Workstation, Player, Server or ACE
  set_kb_item(name:"VMware/Win/Installed", value:TRUE);
  set_kb_item(name:"VMware/" + product + "/Win/Ver", value:vmwareVer);
  security_note(data:"VMware version " + vmwareVer +
                                            " was detected on the host");

  ## build cpe and store it as host_detail  
  for (i = 0; i < VMWARE_MAX-1; i = i + 2) {

     register_cpe(tmpVers:vmwareVer, tmpExpr:VMWARE_LIST[i], tmpBase:VMWARE_LIST[i+1]);
  }

  if(vmwareBuild){
    set_kb_item(name:"VMware/" + product + "/Win/Build", value:vmwareBuild);
  }
}
