###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_visual_prdts_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Microsoft Visual Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script finds the installed product version of Microsoft Visual
  Product(s) and sets the result in KB.";

if(description)
{
  script_id(900808);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-08-03 06:30:10 +0200 (Mon, 03 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Microsoft Visual Products Version Detection");
  desc ="

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Visual Product(s)");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900808";
SCRIPT_DESC = "Microsoft Visual Products Version Detection";

NET_LIST = make_list("^(7\..*)", "cpe:/a:microsoft:visual_studio_.net:2003",
                     "^(8\..*)", "cpe:/a:microsoft:visual_studio_.net:2005",
                     "^(9\..*)", "cpe:/a:microsoft:visual_studio_.net:2008");
NET_MAX = max_index(NET_LIST);

STUDIO_LIST = make_list("^(7\..*)", "cpe:/a:microsoft:visual_studio:2003",
                        "^(8\..*)", "cpe:/a:microsoft:visual_studio:2005",
                        "^(9\..*)", "cpe:/a:microsoft:visual_studio:2008");
STUDIO_MAX = max_index(STUDIO_LIST);

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

# Check for Product Existence
if(!registry_key_exists(key:"SOFTWARE\Microsoft\VisualStudio")){
  exit(0);
}

visual_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
foreach item (registry_enum_keys(key:visual_key))
{
  visualName = registry_get_sz(key:visual_key + item, item:"DisplayName");
  # Set the KB item for Microsoft Visual Studio
  if(visualName =~ "Microsoft Visual Studio [0-9]+")
  {
    studioVer = registry_get_sz(key:visual_key + item, item:"DisplayVersion");
    if(studioVer != NULL){
      set_kb_item(name:"Microsoft/VisualStudio/Ver", value:studioVer);
      security_note(data:visualName + " was detected on the host");

      ## build cpe and store it as host_detail  
      for (i = 0; i < STUDIO_MAX-1; i = i + 2) {

        register_cpe(tmpVers:studioVer, tmpExpr:STUDIO_LIST[i], tmpBase:STUDIO_LIST[i+1]);
      }
    }
  }

  # Set the KB item for Microsoft Visual Studio .Net
  if(visualName =~ "Visual Studio \.NET [A-Za-z0-9]+")
  {
    netVer = registry_get_sz(key:visual_key + item, item:"DisplayVersion");
    if(netVer != NULL){
      set_kb_item(name:"Microsoft/VisualStudio.Net/Ver", value:netVer);
      security_note(data:"Microsoft " + visualName + " was detected on the host");

      ## build cpe and store it as host_detail  
      for (i = 0; i < NET_MAX-1; i = i + 2) {

        register_cpe(tmpVers:netVer, tmpExpr:NET_LIST[i], tmpBase:NET_LIST[i+1]);
      }
    }
  }
}
