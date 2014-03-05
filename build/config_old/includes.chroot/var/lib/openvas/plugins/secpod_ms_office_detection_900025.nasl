###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_detection_900025.nasl 42 2013-11-04 19:41:32Z jan $
#
# Microsoft Office Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Regex pattern modified to match proper Office 2007.
#  - By Chandan S <schandan@secpod.com> On 2009-11-11 #5697
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_summary = "This script will Detect Microsoft Office Version and sets the
  result in KB.";

if(description)
{
  script_id(900025);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Microsoft Office Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Microsoft Office");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Windows");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900025";
SCRIPT_DESC = "Microsoft Office Version Detection";

TMP_OFFICE_LIST = make_list( "^(9\..*)",  "cpe:/a:microsoft:office:2000",
                             "^(10\..*)", "cpe:/a:microsoft:office:2002",
                             "^(11\..*)", "cpe:/a:microsoft:office:2003",
                             "^(12\..*)", "cpe:/a:microsoft:office:2007",
                             "^(14\..*)", "cpe:/a:microsoft:office:2010",
                             "^(15\..*)", "cpe:/a:microsoft:office:2013");

MAX = max_index(TMP_OFFICE_LIST);


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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  MSOffName = registry_get_sz(key:key + item, item:"DisplayName");
  if(egrep(pattern:"Microsoft Office.* Viewer", string:MSOffName))
  {
     MSOffVer = registry_get_sz(key:key + item, item:"DisplayVersion");
     if(MSOffVer){
       set_kb_item(name:"MS/Office/Viewer/Ver", value:MSOffVer);
       security_note(data:MSOffName + " was detected on the host");

       ## build cpe and store it as host_detail
       register_cpe(tmpVers:MSOffVer, tmpExpr:"^([0-9.]+)", tmpBase:"");

     }
     continue;
  }

  if(egrep(pattern:"Microsoft Office (2000|XP|.* Edition 2003$|[^L)].* 2007$|.* 2010$|.*2013$)",
           string:MSOffName))
  {
    MSOffVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(MSOffVer)
    {
      MSOffLoc= registry_get_sz(key:key + item, item:"InstallLocation");        
      if(!MSOffLoc){
        MSOffLoc = "Could not find the install location from registry";
      }
     
      set_kb_item(name:"MS/Office/InstallPath", value:MSOffLoc);
      set_kb_item(name:"MS/Office/Ver", value:MSOffVer);

      security_note(data:MSOffName + " was detected on the host");
      ## build cpe and store it as host_detail  
      for (i = 0; i < MAX-1; i = i + 2) {
         
         register_cpe(tmpVers:MSOffVer, tmpExpr:TMP_OFFICE_LIST[i], tmpBase:TMP_OFFICE_LIST[i+1]);
      }
    }
    continue;
  }
}
