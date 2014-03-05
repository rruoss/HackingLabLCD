###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_detect_win.nasl 42 2013-11-04 19:41:32Z jan $
#
# Mozilla Thunderbird Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated by: Madhuri D <dmadhuri@secpod.com> on 2011-09-08
#    Added security_note to display the version of thunderbird
#
# Update By:  Rachana Shetty <srachana@secpod.com> on 2012-11-27
# Updated to detect ThunderBird ESR version and according to CR-57
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-23
# According to new style script_tags and Fixed issue in identifying ESR.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800015";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-06 13:07:14 +0200 (Mon, 06 Oct 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Mozilla Thunderbird Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Mozilla Thunderbird on Windows.

The script logs in via smb, searches for Mozilla thunderBird in the registry
and gets the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Mozilla Thunderbird on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");


## Variable Initialization
tbirdVer = "";
appPath = "";
birdVer = "";
path = "";
cpe = "";

foreach regKey (make_list("SOFTWARE\Mozilla", "SOFTWARE\mozilla.org"))
{
  if(registry_key_exists(key: regKey))
  {
    # Get ThunderBird Version from Registry
    birdVer = registry_get_sz(item:"CurrentVersion",
                              key: regKey + "\Mozilla Thunderbird");

    if(birdVer)
    {
      # Special case for thunderbird 1.5 (Get the version from file)
      if(birdVer =~ "^(1.5)")
      {
       filePath = registry_get_sz(item:"PathToExe",
                                   key: regKey + "\Mozilla Thunderbird 1.5\bin");
        if(!filePath)
          exit(0);

        tbirdVer = GetVersionFromFile(file: filePath,verstr: "prod");
        if(!tbirdVer) exit(0);
      }
      else
      {
        birdVer = eregmatch(pattern:"[0-9.]+", string:birdVer);
        if(birdVer[0])
          tbirdVer = birdVer[0];
      }

      # Check for ESR installation
      path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");
      if(!path) exit(0);

      appPath = path + "\Mozilla Thunderbird";
      exePath = appPath + "\update-settings.ini";

      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

      ## Read the content of .ini file
      readmeText = read_file(share:share, file:file, offset:0, count:3000);

      if(readmeText && readmeText =~ "comm-esr")
      {
        set_kb_item(name:"Thunderbird-ESR/Win/Ver", value:tbirdVer);

        ## build cpe
        cpe = build_cpe(value:tbirdVer, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:thunderbird_esr:");
        if(isnull(cpe))
          cpe = "cpe:/a:mozilla:thunderbird_esr";

        appName = 'Mozilla ThunderBird ESR';
      }
      else
      {
        set_kb_item(name:"Thunderbird/Win/Ver", value:tbirdVer);

        ## build cpe
        cpe = build_cpe(value:tbirdVer, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:thunderbird:");
        if(isnull(cpe))
          cpe = "cpe:/a:mozilla:thunderbird";

        appName = 'Mozilla ThunderBird';
      }

      register_product(cpe:cpe, location:appPath, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app: appName, version: tbirdVer,
                                               install: appPath, cpe:cpe, concluded:tbirdVer));
      exit(0);
    }
  }
}
