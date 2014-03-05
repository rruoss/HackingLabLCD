###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ida_pro_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Hex-Rays IDA Pro Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the installed Hex-Rays IDA Pro version and saves
  the version in KB.";

if(description)
{
  script_id(901188);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Hex-Rays IDA Pro Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of IDA Pro in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901188";
SCRIPT_DESC = "Hex-Rays IDA Pro Version Detection";

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Install Location From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("IDA Pro" >< name)
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    break;
  }
}

if(path)
{
  ## Get IDA Pro Version
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:path);
  idaVer = GetVer(share:share, file:file);
  if(!idaVer){
    exit(0);
  }

  ## Set IDA Pro Version in KB
  set_kb_item(name:"IDA/Pro/Ver", value:idaVer);
  security_note(data:"IDA Pro Version " + idaVer +
                     " installed at location " + path +
                     " was detected on the host");
      
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:idaVer, exp:"^([0-9.]+)", base:"cpe:/a:hex-rays:ida:5.7::");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
