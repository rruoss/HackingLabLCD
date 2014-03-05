##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_dir_server_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Sun Java Directory Server Version Detection (Win)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated to Detect 6 Series Versions
#  - By Sharath S <sharaths@secpod.com> On 2009-12-31 #6445
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
tag_summary = "This script detects the version of Directory Server and sets
  the reuslt in KB.";

if(description)
{
  script_id(900492);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sun Java Directory Server Version Detection (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Java Directory Server");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900492";
SCRIPT_DESC = "Sun Java Directory Server Version Detection (Win)";

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

key1 = "SOFTWARE\Sun Microsystems\DirectoryServer\";
key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Directory Server\";

if(registry_key_exists(key:key1))
{
  foreach item (registry_enum_keys(key:key1))
  {
    ver = eregmatch(pattern:"([0-9]\.[0-9.]+)", string:item);
    if(ver[1] != NULL){
      set_kb_item(name:"Sun/JavaDirServer/Win/Ver", value:ver[1]);
      security_note(data:"Java Directory Server version " + ver[1] +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:ver[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:sun:java_system_directory_server:");
    }
  }
}

else if(registry_key_exists(key:key2))
{
  appregCheck = registry_get_sz(key:key2, item:"DisplayName");
  if("Directory Server" >< appregCheck)
  {
    infPath = registry_get_sz(key:key2, item:"UninstallString");
    infPath = ereg_replace(pattern:'"', string:infPath, replace:"");
    infFile = infPath - "uninstall_dirserver.exe" + "setup\slapd\slapd.inf";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:infFile);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:infFile);

    infContent = read_file(share:share, file:file, offset:0, count:256);
    if("Directory Server" >< infContent)
    {
      appVer = eregmatch(pattern:"System Directory Server ([0-9]\.[0-9.]+)",
                         string:infContent);
      if(appVer[1] != NULL){
        set_kb_item(name:"Sun/JavaDirServer/Win/Ver", value:appVer[1]);
        security_note(data:"Java Directory Server version " + appVer[1] +
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:ver[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:sun:java_system_directory_server:");
      }
    }
  }
}
