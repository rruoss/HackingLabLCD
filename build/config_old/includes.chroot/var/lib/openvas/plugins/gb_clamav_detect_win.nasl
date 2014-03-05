###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# ClamAV Version Detection (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Modified By: Antu sanadi <santu@secpod.com> on 2010-04-09
# Modified to detect version of latest products also
#
# Modified By: Madhuri D <dmadhuri@secpod.com> on 2011-08-27
# Modified to detect latest version
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script retrieves ClamAV Version for Windows and saves the
  result in KB.";

if(description)
{
  script_id(800555);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ClamAV Version Detection (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Set Version of ClamAV in KB for Windows");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800555";
SCRIPT_DESC = "ClamAV Version Detection (Win)";

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  clamName = registry_get_sz(key:key + item, item:"DisplayName");
  if("ClamWin" >< clamName)
  {
    clamVer = eregmatch(pattern:"ClamWin Free Antivirus ([0-9.]+)", string:clamName);
    if(clamVer[1] != NULL)
    {
      set_kb_item(name:"ClamAV/Win/Ver", value:clamVer[1]);
      security_note(data:"Clam Anti Virus version " + clamVer[1] + " was detected" +
                         " on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:clamVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:clamav:clamav:");

      exit(0);
    }
  }
}

key = key + "Immunet Protect\";
clamname = registry_get_sz(key:key , item:"DisplayName");
if("ClamAV for Windows"  >< clamname || "Immunet" >< clamname)
{
  clamVer = registry_get_sz(key:key , item:"DisplayVersion");
  if(clamVer)
  {
    set_kb_item(name:"ClamAV/Win/Ver", value:clamVer);
    security_note(data:"Clam Anti Virus version " + clamVer + " was detected" +
                         " on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:clamVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:clamav:clamav:");

  }
}
