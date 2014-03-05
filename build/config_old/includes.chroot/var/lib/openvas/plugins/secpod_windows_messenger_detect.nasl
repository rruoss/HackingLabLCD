###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_windows_messenger_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Microsoft MSN Messenger Service Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_summary = "Detection of installed version of Microsoft MSN Messenger.

The script logs in via smb, searches for Microsoft MSN Messenger in the
registry and gets the exe file path from 'InstallationDirectory' string
in registry and version from the 'msmsgs.exe'";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902915";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"registry version check");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-05-30 14:53:42 +0530 (Wed, 30 May 2012)");
  script_name("Microsoft MSN Messenger Service Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Microsoft MSN Messenger Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");


## Variable Initialization
path = "";
cpe = NULL;
msnVer = "";

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm application is installed
msnkey = "SOFTWARE\Microsoft\MessengerService";
if(registry_key_exists(key:msnkey) &&
   path = registry_get_sz(key:msnkey, item:"InstallationDirectory"))
{
  ## Get the version from msmsgs.exe
  msnVer = fetch_file_version(sysPath:path, file_name:"msmsgs.exe");
  if(msnVer)
  {
    ## Set the KB item
    set_kb_item(name:"Microsoft/MSN/Messenger/Ver", value:msnVer);
    cpe = build_cpe(value:msnVer, exp:"^([0-9.]+)",
                    base:"cpe:/a:microsoft:msn_messenger:");

    if(!isnull(cpe))
      register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

    log_message(data: build_detection_report(app:"Microsoft MSN Messenger Service",
                                         version:msnVer,
                                         install:path,
                                         cpe:cpe,
                                         concluded: msnVer));
  }
}
