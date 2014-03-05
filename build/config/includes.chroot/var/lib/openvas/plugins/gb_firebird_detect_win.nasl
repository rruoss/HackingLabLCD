###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firebird_detect_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Firebird SQL Version Detection (Win)
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
tag_summary = "This script detects the installed version of Firebird SQL and
  sets the result in KB.";

if(description)
{
  script_id(800851);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Firebird SQL Version Detection (Win)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Firebird SQL in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800851";
SCRIPT_DESC = "Firebird SQL Version Detection (Win)";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Firebird Project\Firebird Server")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  # Check for Firebird DisplayName
  firebirdName = registry_get_sz(key:key + item, item:"DisplayName");
  if(firebirdName =~ "Firebird [0-9.]+")
  {
    # Check for Firebird DisplayVersion
    firebirdVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(isnull(firebirdVer))
    {
      firePath = registry_get_sz(key:key + item, item:"DisplayIcon");
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:firePath);
      fire = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:firePath);

      # Check for Firebird .exe File Version
      firebirdVer = GetVer(file:fire, share:share);
    }

    # Set KB for Firebird
    if(!isnull(firebirdVer))
    {
      set_kb_item(name:"Firebird-SQL/Ver", value:firebirdVer);
      security_note(data:"Firebird SQL version " + firebirdVer + " running at" + 
                          " location " + firePath + " was detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:firebirdVer, exp:"^([0-9.]+)", base:"cpe:/a:firebirdsql:firebird:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
