###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yahoo_msg_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Yahoo! Messenger Version Detection
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
tag_summary = "This script detects the installed version of Yahoo! Messenger
  and sets the result in KB.";

if(description)
{
  script_id(801149);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Yahoo! Messenger Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Yahoo! Messenger");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801149";
SCRIPT_DESC = "Yahoo! Messenger Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Yahoo! Messenger";
ymsgName = registry_get_sz(key:path, item:"DisplayName");

if("Yahoo! Messenger" >< ymsgName)
{
  ymsgVer = registry_get_sz(key:"SOFTWARE\yahoo\pager", item:"ProductVersion");
  if(isnull(ymsgVer))
  {
    ymsgPath = registry_get_sz(key:path, item:"DisplayIcon");
    ymsgPath = ymsgPath - ",-0";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ymsgPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ymsgPath);
    ymsgVer = GetVer(share:share, file:file);
  }

  if(ymsgVer){
    set_kb_item(name:"YahooMessenger/Ver", value:ymsgVer);
    security_note(data:"Yahoo! Messenger Version " + ymsgVer +
             " running at location " + ymsgPath + " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ymsgVer, exp:"^([0-9.]+)", base:"cpe:/a:yahoo:messenger:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
