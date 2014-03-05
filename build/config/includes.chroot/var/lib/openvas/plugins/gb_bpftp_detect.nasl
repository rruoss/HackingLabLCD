###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpftp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# BulletProof FTP Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed BulletProof FTP Version and
  saves the version in KB.";

if(description)
{
  script_id(800329);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("BulletProof FTP Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of BulletProof FTP in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800329";
SCRIPT_DESC = "BulletProof FTP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
      "\BulletProof FTP Client_is1";
if("BulletProof FTP Client" >< registry_get_sz(key:key, item:"DisplayName"))
{
  exePath = registry_get_sz(key:key, item:"DisplayIcon");
  if(!exePath){
    exit(0);
  }
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

  bpftpVer = GetVer(file:file, share:share);

  # Set the Version in KB
  if(bpftpVer)
  {
    set_kb_item(name:"BulletProof/Client/Ver", value:bpftpVer);
    security_note(data:"Bullet Proof FTP Client version " + bpftpVer + " running"+ 
                       " at location " + exePath + " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:bpftpVer, exp:"^([0-9.]+)", base:"cpe:/a:bpftp:bulletproof_ftp_client:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
