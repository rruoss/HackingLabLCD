##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_detect_win_900003.nasl 51 2013-11-08 15:12:40Z veerendragg $
#
# Apple Safari Detect Script (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Update By:  Shakeel <bshakeel@secpod.com> on 2013-11-05
# According to CR57 and new style script_tags.
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900003";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 51 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-08 16:12:40 +0100 (Fr, 08. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Apple Safari Detect Script (Windows)");

  tag_summary =
"Detection of installed version of Apple Safari on Windows.

The script logs in via smb, searches for Apple Safari in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check for Apple Safari version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright 2008 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Apple Computer, Inc.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  safariName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Safari" >< safariName)
  {
    safariPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(safariPath)
    {
      safariVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(safariVer)
      {
        set_kb_item(name:"AppleSafari/Version", value:safariVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:safariVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:safari:");
        if(isnull(cpe))
          cpe="cpe:/a:apple:safari";

        register_product(cpe: cpe, location: safariPath, nvt: SCRIPT_OID);

        log_message(data: build_detection_report(app: safariName,
                                              version: safariVer,
                                             install: safariPath,
                                             cpe: cpe,
                                             concluded: safariVer));
      }
    }
  }
}
