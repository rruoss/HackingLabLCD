###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aimp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# AIMP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Modified the file string.
# - By Nikita MR <rnikita@secpod.com> On 2009-09-15 #4729
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
tag_summary = "This script detects the installed version of AIMP player and sets
  the version in KB.";

if(description)
{
  script_id(800590);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("AIMP Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for the version of AIMP");
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

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800590";
SCRIPT_DESC = "AIMP Version Detection";

if(!get_kb_item("SMB/WindowsVersion"))
{
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AIMP2";
appName = registry_get_sz(key:key, item:"DisplayName");

if("AIMP2" >< appName)
{
  aimpPath = registry_get_sz(key:key + item, item:"UninstallString");

  if(aimpPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:aimpPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:aimpPath -
                        "\UnInstall.exe" - "Uninstall.exe" + "\AIMP2.exe");
    aimpVer = GetVer(share:share, file:file);

    if(aimpVer != NULL)
    {
      set_kb_item(name:"AIMP/Ver", value:aimpVer);
      security_note(data:"AIMP2 version " + aimpVer + " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: aimpVer, exp:"[0-9.]+([a-z0-9]+)?)",base:"cpe:/a:aimp:aimp2_audio_converter:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
