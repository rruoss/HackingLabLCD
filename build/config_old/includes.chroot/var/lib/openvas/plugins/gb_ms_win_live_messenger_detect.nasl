###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_live_messenger_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows Live Messenger Client Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Update to detect the Messenger Plus! Live
#  - By Sharath S <sharaths@secpod.com> on 2009-07-31
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
tag_summary = "This script detects the version of Microsoft Windows Live Messenger
  Client on remote host and sets the KB.";

if(description)
{
  script_id(800331);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Microsoft Windows Live Messenger Client Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Windows Live Messenger");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800331";
SCRIPT_DESC = "Microsoft Windows Live Messenger Client Version Detection";

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

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows Live\Messenger")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  # Windows Live Messenger
  if("Windows Live Messenger" >< registry_get_sz(key:key + item,
                                                 item:"DisplayName"))
  {
    livemgrVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    # Set KB for Windows Live Messenger
    if(!isnull(livemgrVer)){
      set_kb_item(name:"MS/LiveMessenger/Ver", value:livemgrVer);

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:livemgrVer, tmpExpr:"^([0-9]\.[0-9]\.[0-9])", tmpBase:"cpe:/a:microsoft:windows_live_messenger:");

    }
  }

  # Messenger Plus! 
  if("Messenger Plus!" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    msgPlusVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    plusPath = registry_get_sz(key:key + item, item:"UninstallString");
    plusPath = eregmatch(pattern:'"(.*)"', string:plusPath);

    if(isnull(msgPlusVer))
    {
      share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:plusPath[1]);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:plusPath[1]);

      if("Uninstall.exe" >< file)
      {
        file -= "Uninstall.exe" + "MPTools.exe";
        msgPlusVer = GetVer(file:file, share:share);
      }
      else if("MsgPlus.exe" >< file)
        msgPlusVer = GetVer(file:file, share:share);
    }

    # Set KB for Version and Path of Messenger Plus!
    if(!isnull(msgPlusVer))
    {
      set_kb_item(name:"MS/MessengerPlus/Ver", value:msgPlusVer);
      set_kb_item(name:"MS/MessengerPlus/Path", value:plusPath[1]);
      security_note(data:"Microsoft Windows Live Messenger Client version " + msgPlusVer 
                         + " running at location " + plusPath[1] + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:msgPlusVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:microsoft:messenger_plus%21_live:");

    }
  }
}
