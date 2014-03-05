##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_av_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Kaspersky AntiVirus Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated to detect Kaspersky Internet Security and Anti-Virus for
# Windows File Servers.
# By - Nikita MR <rnikita@secpod.com> on 2010-01-06
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
tag_summary = "This script finds the installed Kaspersky AntiVirus and
  saves the version in KB.";

if(description)
{
  script_id(800241);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Kaspersky AntiVirus Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Kaspersky AntiVirus in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800241";
SCRIPT_DESC = "Kaspersky AntiVirus Version Detection";

INTNETSEC_LIST = make_list( "^(7\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security:",
                         "^(8\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2009:",
                         "^(9\..*)", "cpe:/a:kaspersky_lab:kaspersky_internet_security_2010:");
INTNETSEC_MAX = max_index(INTNETSEC_LIST);

AV_LIST = make_list("^(9\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2010",
                    "^(8\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2009",
                    "^(7\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2008", 
                    "^(6\..*)", "cpe:/a:kaspersky:kaspersky_anti-virus:2007");
AV_MAX = max_index(AV_LIST);

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

if(!registry_key_exists(key:"SOFTWARE\KasperskyLab")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kaspersky" >< prdtName)
  {
    # Check for Kaspersky Anti-Virus for Windows Workstations.
    if("Anti-Virus" >< prdtName && "Windows Workstations" >< prdtName)
    {
      kavwVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(kavwVer != NULL)
      {
        set_kb_item(name:"Kaspersky/AV-Workstation/Ver", value:kavwVer);
        security_note(data:"Kaspersky Anti-Virus version " + kavwVer +
                                   " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:kavwVer, tmpExpr:"^(6\.0)", tmpBase:"cpe:/a:kaspersky_lab:kaspersky_anti-virus:6.0::workstations");

      }
      exit(0);
    }

    # Check for Kaspersky Anti-Virus for Windows File Servers.
    if("Anti-Virus" >< prdtName && "File Servers" >< prdtName)
    {
      kavsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(kavsVer != NULL)
      {
        set_kb_item(name:"Kaspersky/AV-FileServer/Ver", value:kavsVer);
        security_note(data:"Kaspersky Anti-Virus version " + kavsVer +
                         " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:kavsVer, tmpExpr:"^(6\.0)", tmpBase:"cpe:/a:kaspersky_lab:kaspersky_anti-virus:6.0.3.837::windows_file_servers:");

      }
      exit(0);
    }

    # Check for Kaspersky Anti-Virus.
    if(prdtName =~ "Kaspersky Anti-Virus [0-9]+")
    {
      kavVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(kavVer != NULL)
      {
        set_kb_item(name:"Kaspersky/AV/Ver", value:kavVer);
        security_note(data:"Kaspersky Anti-Virus version " + kavVer +
                         " was detected on the host");

        ## build cpe and store it as host_detail  
        for (i = 0; i < AV_MAX-1; i = i + 2) {
 
          register_cpe(tmpVers:kavVer, tmpExpr:AV_LIST[i], tmpBase:AV_LIST[i+1]);
        }
      }
      exit(0);
    }

    # Check for Kaspersky Internet Security.
    if("Internet Security" >< prdtName)
    {
      kisVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(kisVer != NULL)
      {
        set_kb_item(name:"Kaspersky/IntNetSec/Ver", value:kisVer);
        security_note(data:" Kaspersky Internet Security version " + kisVer
                                     + " was detected on the host");

        ## build cpe and store it as host_detail  
        for (i = 0; i < INTNETSEC_MAX-1; i = i + 2) {

          register_cpe(tmpVers:kisVer, tmpExpr:INTNETSEC_LIST[i], tmpBase:INTNETSEC_LIST[i+1]);
        }
      }
      exit(0);
    }
  }
}
