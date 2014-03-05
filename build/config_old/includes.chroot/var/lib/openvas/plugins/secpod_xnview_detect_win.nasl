###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xnview_detect_win.nasl 44 2013-11-04 19:58:48Z jan $
#
# XnView Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900751";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_tag(name:"detection", value:"registry version check");
  script_name("XnView Version Detection");

  tag_summary =
"Detection of installed version of XnView.

The script logs in via smb, searches for XnView in the registry and
gets the version from 'DisplayVersion' string in registry";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set KB for the version of XnView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

key = "";
xnviewVer= "";
insloc= "";

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check existance of XnView
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get XnView Version
xnviewVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!xnviewVer){
  exit(0);
}

insloc = registry_get_sz(key:key, item:"InstallLocation");
if(!insloc){
  insloc = "Could not find the install location from registry";
}


set_kb_item(name:"XnView/Win/Ver", value:xnviewVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:xnviewVer, exp:"^([0-9.]+)", base:"cpe:/a:xnview:xnview:");
if(isnull(cpe))
  cpe = "cpe:/a:xnview:xnview";

register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

log_message(data: build_detection_report(app:"XnView ",
                                         version:xnviewVer,
                                         install:insloc,
                                         cpe:cpe,
                                         concluded:xnviewVer));
