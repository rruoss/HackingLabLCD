###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trellian_ftp_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Trellian FTP Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the installed Trellian FTP version and saves the
  result in KB.";

if(description)
{
  script_id(901108);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_name("Trellian FTP Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Trellian FTP in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901108";
SCRIPT_DESC = "Trellian FTP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\TRELLIAN\Trellian FTP")){
  exit(0);
}

trellianPath = registry_get_sz(key:"SOFTWARE\TRELLIAN\LiveUpgrade\Components" +
                                                 "\Trellian FTP", item:"path");
if(!trellianPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:trellianPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:trellianPath);

## Get Trellian FTP Version
trellianVer = GetVer(share:share, file:file);
if(trellianVer)
{
  ## Set Trellian FTP Version in KB
  set_kb_item(name:"TrellianFTP/Version", value:trellianVer);
  security_note(data:"Trellian FTP version " + trellianVer + " running at " +
                     "location " + trellianPath + " was detected on the host");
      
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:trellianVer, exp:"^([0-9.]+)", base:"cpe:/a:trellian:ftp:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
