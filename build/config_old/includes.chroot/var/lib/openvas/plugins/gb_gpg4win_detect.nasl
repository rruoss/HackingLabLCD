###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gpg4win_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gpg4win And Components Version Detection (Win)
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
tag_summary = "This script detects the installed product version of Gpg4win and
  its components and sets the results in KB.";

if(description)
{
  script_id(801128);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Gpg4win And Components Version Detection (Win)");
  desc ="
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Gpg4win");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801128";
SCRIPT_DESC = "Gpg4win And Components Version Detection (Win)";

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GPG4Win";
gpgName = registry_get_sz(key:key, item:"DisplayName");

if("Gpg4win" >< gpgName || ("GnuPG" >< gpgName))
{
  gpgVer = registry_get_sz(key:key, item:"DisplayVersion");
  gpgVer = ereg_replace(pattern:"-", replace:".", string:gpgVer);

  # Set KB for Gpg4Win
  if(gpgVer != NULL)
  {
    set_kb_item(name:"Gpg4win/Win/Ver", value:gpgVer);
 
    ## build cpe and store it as host_detail
    register_cpe(tmpVers:gpgVer, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:gpg4win:gpg4win:");


    gpgPath = registry_get_sz(key:key, item:"InstallLocation");
    if(gpgPath)
    {
      gpgPath += "\share\gpg4win\README.en.txt";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:gpgPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:gpgPath);
      txtRead = read_file(share:share, file:file, offset:2000, count:10000);

      # Set KB for Kleopatra
      kleoVer = eregmatch(pattern:"Kleopatra: +([0-9.]+)", string:txtRead);
      if(kleoVer[1])
      {
        set_kb_item(name:"Kleopatra/Win/Ver", value:kleoVer[1]);
        security_note(data:"Kleopatra version " + kleoVer[1] + 
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:kleoVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:kde-apps:kleopatra:");

      }

      # Set KB for GNU Privacy Assistant
      gpaVer = eregmatch(pattern:"GPA: +([0-9.]+)", string:txtRead);
      if(gpaVer[1])
      {
        set_kb_item(name:"GPA/Win/Ver", value:gpaVer[1]);
        security_note(data:"GNU Privacy Assistant version " + gpaVer[1] + 
                           " was detected on the host");
      }
    }
  }
}
