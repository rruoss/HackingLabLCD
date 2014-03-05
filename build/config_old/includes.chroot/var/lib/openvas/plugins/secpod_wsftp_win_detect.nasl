###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_wsftp_win_detect.nasl 1083 2009-03-09 17:05:29Z Feb $
#
# WS_FTP Server Checking
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script determines the WsFtp server version on the remote host
  and sets the result in the KB.";
if(description)
{
  script_id(900608);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name( "WS_FTP Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB of WsFTP version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod.");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900608";
SCRIPT_DESC = "WS_FTP Version Detection";

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("WS_FTP Server" >< banner)
{
  wsVer = eregmatch(pattern:"WS_FTP Server ([0-9.]+)", string:banner);
  if(wsVer[1] != NULL){
    set_kb_item(name:"WSFTP/Win/Ver", value:wsVer[1]);
    security_note(data:"WS_FTP version " + wsVer[1] +
                       " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: wsVer[1], exp:"^([0-9.]+)",base:"cpe:/a:ipswitch:ws_ftp:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
