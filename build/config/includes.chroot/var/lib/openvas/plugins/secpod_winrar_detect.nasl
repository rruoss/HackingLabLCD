##############################################################################
# OpenVAS Vulnerability Test
# $ secpod_winrar_detect.nasl 4470 2009-09-15 13:10:24Z sep $
#
# WinRAR Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http//www.secpod.com
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
tag_summary = "This script finds the installed WinRAR and saves the
  version in KB.";

if(description)
{
  script_id(901021);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("WinRAR Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of WinRAR in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901021";
SCRIPT_DESC = "WinRAR Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe";
if(!registry_key_exists(key:key))
{
  exit(0);
}

path =  registry_get_sz(key:key, item:"Path");

if("WinRAR" >< path)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path +"\WinRAR.exe");

  rarVer = GetVer(file:file, share:share);

  if(isnull(rarVer))
  {
    path = path + "\WhatsNew.txt";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

    rarVer = read_file(share:share, file:file, offset:0, count:1000);
    if(rarVer != NULL)
    {
      rarVer = eregmatch(pattern:"[v|V]ersion ([0-9.]+)", string:rarVer);
      if(rarVer[1] != NULL){
         rarVer = rarVer[1];
      }
    }
  }

 set_kb_item(name:"WinRAR/Ver", value:rarVer);
 security_note(data:"WinRAR version " + rarVer + " was detected on the host");
   
 ## build cpe and store it as host_detail
 cpe = build_cpe(value:rarVer, exp:"^([0-9.]+)", base:"cpe:/a:rarlab:winrar:");
 if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
