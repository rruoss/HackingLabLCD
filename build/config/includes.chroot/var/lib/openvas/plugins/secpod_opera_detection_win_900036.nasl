###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_detection_win_900036.nasl 78 2013-11-26 14:37:17Z veerendragg $
#
# Opera Version Detection for Windows
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Update By:  Shakeel <bshakeel@secpod.com> on 2013-10-03
# According to cr57 and new style script_tags.
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# Modified to detect Beta Versions
#  - Sharath S <sharaths@secpod.com> On 2009-09-03
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
################################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900036";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 78 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-26 15:37:17 +0100 (Tue, 26 Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Opera Version Detection for Windows");

  tag_summary =
"Detection of installed version of Opera on Windows.

The script logs in via smb, searches for Opera in the registry and gets
the version from registry.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Opera on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
operaVersion = "";
operaflag = 1;
operaPath = "";
operaName = "";
operaVer = "";
key = "";
ver = "";

function OperaSet(operaVersion, operaName, operaPath)
{
  set_kb_item(name:"Opera/Build/Win/Ver", value:operaVersion);
  ver = eregmatch(pattern:"^([0-9]+\.[0-9]+)", string:operaVersion);
  if(ver[1] != NULL)
  {
    set_kb_item(name:"Opera/Win/Version", value:ver[1]);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:opera:opera_browser:");
    if(isnull(cpe))
      cpe = "cpe:/a:opera:opera_browser";

    register_product(cpe: cpe, location: operaPath, nvt: SCRIPT_OID);

    log_message(data: build_detection_report(app: operaName,
                                             version: ver[1],
                                             install: operaPath,
                                             cpe: cpe,
                                             concluded: operaVersion));
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  operaName = registry_get_sz(key:key + item, item:"DisplayName");
  if( operaName =~ "^Opera ")
  {
    operaPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(operaPath)
    {
      operaVer = fetch_file_version(sysPath: operaPath, file_name:"opera.exe");

      if(operaVer)
      {
        OperaSet(operaVersion: operaVer, operaName: operaName, operaPath: operaPath);
        operaflag = 0;
      }
      else
      {
        operaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(operaVer)
        {
          OperaSet(operaVersion: operaVer, operaName: operaName, operaPath: operaPath);
          operaflag = 0;
        }
      }

    }
    else
    {
      operaPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows" +
                                      "\CurrentVersion", item:"ProgramFilesDir");
      if(operaPath)
      {
        operaPath = operaPath + "\Opera" ;
        operaVer = fetch_file_version(sysPath: operaPath, file_name:"opera.exe");

        if(operaVer)
        {
          OperaSet(operaVersion: operaVer, operaName: operaName, operaPath: operaPath);
          operaflag = 0;
        }
      }
    }
  }
}

if(operaflag)
{
  operaPath = registry_get_sz(key:"SOFTWARE\Netscape\Netscape Navigator"+
              "\5.0, Opera\Main", item:"Install Directory");
  operaPath = operaPath + "\Opera";
  if(operaPath)
  {
    operaVer = fetch_file_version(sysPath: operaPath, file_name:"opera.exe");
    if(operaVer){
      OperaSet(operaVersion: operaVer, operaName: "Opera", operaPath: operaPath);
    }
  }
}
