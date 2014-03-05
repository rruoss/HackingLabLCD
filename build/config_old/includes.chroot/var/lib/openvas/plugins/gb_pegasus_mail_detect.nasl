###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pegasus_mail_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pegasus Mail Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script retrieves the installed version of Pegasus Mail and
  saves the result in KB.";

if(description)
{
  script_id(800969);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Pegasus Mail Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Set the version of Pegasus Mail in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800969";
SCRIPT_DESC = "Pegasus Mail Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pegasus Mail";
pmailName = registry_get_sz(key:key, item:"DisplayName");
if("Pegasus Mail" >< pmailName)
{
  pmailPath = registry_get_sz(key:key, item:"UninstallString");
  if(pmailPath)
  {
    pmailPath =  eregmatch(pattern:"^(.+(exe|EXE))(.*)?$", string:pmailPath);
    if(pmailPath[1] != NULL)
    {
      pmailPath =  pmailPath[1] - "DESETUP.EXE" - "DeSetup.exe" + "winpm-32.exe";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pmailPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:pmailPath);

      pmailVer = GetVer(file:file, share:share);
      if(!isnull(pmailVer))
      {
        set_kb_item(name:"Pegasus/Mail/Ver", value:pmailVer);
        security_note(data:"Pegasus Mail version " + pmailVer +
                           " running at location " + pmailPath +
                           " was detected on the host");
  
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:pmailVer, exp:"^([0-9.]+)", base:"cpe:/a:pmail:pegasus_mail:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}
