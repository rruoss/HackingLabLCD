###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_ftp_server_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# FileCopa FTP Server Version Detection
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
tag_summary = "This script detects the installed version of FileCopa FTP Server
  and sets the result in KB.";

if(description)
{
  script_id(801124);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("FileCopa FTP Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of FileCopa FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801124";
SCRIPT_DESC = "FileCopa FTP Server Version Detection";

filecopePort = get_kb_item("Services/ftp");
if(!filecopePort){
  filecopePort = 21;
}

if(!get_port_state(filecopePort)){
  exit(0);
}

banner = get_ftp_banner(port:filecopePort);
if("FileCOPA FTP Server" >< banner)
{
  filecopeVer = eregmatch(pattern:"FileCOPA FTP Server Version ([0-9.]+)",
                          string:banner);
  if(filecopeVer[1])
  {
    set_kb_item(name:"FileCOPA-FTP-Server/Ver", value:filecopeVer[1]);
    security_note(data:"FileCOPA FTP Server version " + filecopeVer[1] +
                       " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:filecopeVer[1], exp:"^([0-9.]+)", base:"cpe:/a:filecopa-ftpserver:ftp_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
