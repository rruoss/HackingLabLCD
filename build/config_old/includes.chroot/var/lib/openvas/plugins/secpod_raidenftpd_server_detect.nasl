###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_raidenftpd_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# RaidenFTPD Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the installed version of RaidenFTPD Server
  and sets the result in KB.";

if(description)
{
  script_id(900510);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("RaidenFTPD Server Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of RaidenFTPD Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("find_service.nasl", "secpod_reg_enum.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("ftp_func.inc");
include("secpod_smb_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900510";
SCRIPT_DESC = "RaidenFTPD Server Version Detection";

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(!get_port_state(ftpPort)){
  exit(0);
}

if("RaidenFTPD" >!< get_ftp_banner(port:ftpPort)){
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

exePath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services" +
                              "\RaidenFTPDService", item:"ImagePath");
if(!exePath){
  exit(0);
}

exePath = exePath - "rftpdservice.exe" + "raidenftpd.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

rftpdVer = GetVer(file:file, share:share);
if(rftpdVer != NULL){
  set_kb_item(name:"RaidenFTPD/Ver", value:rftpdVer);
  security_note(data:"RaidenFTPD Server version " + rftpdVer + " running at" +
                     " location " + exePath +  " was detected on the host");

  ## build cpe and store it as host_detail
  cpe = build_cpe(value: rftpdVer, exp:"^([0-9.]+)",base:"cpe:/a:raidenftpd:raidenftpd:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
