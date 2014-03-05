###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_free_download_mang_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Free Download Manager Version Detection
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
tag_summary = "This script detects the installed version of Free Download Manager
  and sets the result in KB.";

if(description)
{
  script_id(800348);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Free Download Manager Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Free Download Manager in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800348";
SCRIPT_DESC = "Free Download Manager Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

#Check for Free Download Manager and get the installed path
regPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Free Download Manager_is1",
                          item:"InstallLocation");
if(!regPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:regPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:regPath + "\fdm.exe");

fdmVer = GetVer(share:share, file:file);
if(fdmVer)
{
  set_kb_item(name:"FreeDownloadManager/Ver", value:fdmVer);
  security_note(data:"Free Download Manager version " + fdmVer + " running at" + 
                     " location " + regPath + " was detected on the host");
    
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:fdmVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:free_download_manager:free_download_manager:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
