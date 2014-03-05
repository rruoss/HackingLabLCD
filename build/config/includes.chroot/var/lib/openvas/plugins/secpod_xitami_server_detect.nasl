###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xitami_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xitami Server Version Detection
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
tag_summary = "This script detects the installed version of Xitami Server
  and saves the result in KB.";

if(description)
{
  script_id(900547);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Xitami Server Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of Xitami Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, "Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("http_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900547";
SCRIPT_DESC = "Xitami Server Version Detection";

wwwPort = get_http_port(default:80);
if(!wwwPort){
  wwwPort = 80;
}

if(!get_port_state(wwwPort)){
  exit(0);
}

soc = open_sock_tcp(wwwPort);
if(!soc)exit(0);

req = string("GET /\r\n\r\n", "Host: ", get_host_name(), "\r\n");
send(socket:soc, data:req);
rcvRes = http_recv(socket:soc);
close(soc);

if("Xitami" >!< rcvRes){
  exit(0);
}

xitaVer = eregmatch(pattern:"Xitami\/([0-9]\.[0-9.]+)([a-z][0-9]?)?",
                    string:rcvRes);
if(xitaVer == NULL)
{
  ftpPort = get_kb_item("Services/ftp");

  if(!ftpPort){
    ftpPort = 21;
  }

  if(!get_port_state(ftpPort)){
    exit(0);
  }

  # Get the version from banner
  banner = get_ftp_banner(port:ftpPort);
  xitaVer = eregmatch(pattern:"Xitami.*([0-9]\.[0-9.]+)([a-z][0-9]?)?",
                      string: banner);
}

if(xitaVer[1] != NULL)
{
  if(xitaVer[2] != NULL){
    xVer = xitaVer[1] + "." + xitaVer[2];
  }
  else
    xVer = xitaVer[1];
}

if(xVer){
  set_kb_item(name:"Xitami/Ver", value:xVer);
  security_note(data:"Xitami Server version " + xVer +
                     " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: xVer, exp:"^([0-9.]+([a-z][0-9]?)?)",base:"cpe:/a:imatix:xitami:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
