###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_backup_exec_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Symantec Backup Exec Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
# ###############################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of Symantec Backup Exec
  and sets the result in KB.";

if(description)
{
  script_id(802105);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Symantec Backup Exec Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets Symantec Backup Exec Version in the KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for Symantec Backup Exec for Windows Servers DisplayName
  if((eregmatch(pattern:"^Symantec Backup Exec(.*) Windows Servers$",
              string:registry_get_sz(key:key + item, item:"DisplayName"))))
  {
    ## Get the Symantec Backup Exec version
    symVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(symVer != NULL)
    {
      set_kb_item(name:"Symantec/Backup/Exec/Win/Server", value:symVer);
      security_note(data:"Symantec Backup Exec for Windows Servers version " +
                          symVer + " was detected on the host");
    }
  }

  ## Check for Symantec Backup Exec for 2010 DisplayName
  if((eregmatch(pattern:"^Symantec Backup Exec(.*) 2010$",
              string:registry_get_sz(key:key + item, item:"DisplayName"))))
  {
    ## Get the Symantec Backup Exec version
    symVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(symVer != NULL)
    {
      set_kb_item(name:"Symantec/Backup/Exec/2010", value:symVer);
      security_note(data:"Symantec Backup Exec version for 2010" +
                          symVer + " was detected on the host");
    }
  }
}
