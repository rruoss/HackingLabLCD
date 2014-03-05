##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_servu_ftp_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Rhinosoft Serv-U FTP Server Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "This script finds the installed Rhinosoft Serv-U FTP Server and
  saves the version in KB.";

if(description)
{
  script_id(900482);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:23:52 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Rhinosoft Serv-U FTP Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Rhinosoft Serv-U FTP Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900482";
SCRIPT_DESC = "Rhinosoft Serv-U FTP Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Serv-U";
if(!registry_key_exists(key:key)){
  exit(0);
}

path = registry_get_sz(key:key, item:"Path");
if(path != NULL)
{
  path = path + "\Serv-U.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
  version = GetVer(file: file, share:share);
  if(!isnull(version)) {
    set_kb_item(name:"Serv-U/FTPServ/Ver", value:version);
    security_note(data:"Rhinosoft Serv-U FTP Server version " + version +
                       " running at location " + path +
                       " was detected on the host");
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:rhinosoft:serv-u:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }  
}
