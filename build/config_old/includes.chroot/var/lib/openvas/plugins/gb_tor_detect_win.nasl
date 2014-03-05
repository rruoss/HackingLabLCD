###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Tor Version Detection (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated to detect for Beta and RC Versions
#   - By Sharath S <sharaths@secpod.com> on 2009-07-13
#
# Updated to detect version from Uninstall.exe
#   - By N Shashi Kiran N <nskiran@secpod.com> on 2011-06-16
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
tag_summary = "This script is detects the installed version of Tor and
  sets the result in KB.";

if(description)
{
  script_id(800351);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Tor Version Detection (Win)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Tor");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800351";
SCRIPT_DESC = "Tor Version Detection (Win)";

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

torName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Tor", item:"DisplayName");
if("Tor" >< torName)
{
  torVer = eregmatch(pattern:"Tor ([0-9.]+-?([a-z0-9]+)?)", string:torName);
  if(torVer[1] != NULL)
  {
    set_kb_item(name:"Tor/Win/Ver", value:torVer[1]);
    security_note(data:"Tor version " + torVer[1] +
                         " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:torVer[1], tmpExpr:"^([0-9.]+)-?([a-z0-9]+)?", tmpBase:"cpe:/a:tor:tor:");

  }
  else
  {
    torName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\Tor", item:"UninstallString");
    if("Tor" >< torName)
    {
      torName = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:torName);
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:torName);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:torName);

      torVer = GetVer(file:file, share:share);
      if(torVer)
      {
        set_kb_item(name:"Tor/Win/Ver", value:torVer);
        security_note(data:"Tor version " + torVer +
                         " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers: torVer, tmpExpr:"^([0-9.]+)-?([a-z0-9]+)?", tmpBase:"cpe:/a:tor:tor:");

      }
    }
  }
}
