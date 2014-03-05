###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# MapServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script detects the installed version of MapServer
  and sets the result in KB.";

if(description)
{
  script_id(800547);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("MapServer Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for Version of MapServer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800547";
SCRIPT_DESC = "MapServer Version Detection";

mapPort = get_kb_item("Services/www");
if(!mapPort){
  mapPort = 80;
}

if(!get_port_state(mapPort)){
  exit(0);
}

sndReq = http_get(item:string("/cgi-bin/mapserv?map="), port:mapPort);
rcvRes = http_keepalive_send_recv(port:mapPort, data:sndReq, bodyonly:1);

if("MapServer" >!< rcvRes)
{
  sndReq = http_get(item: string("/cgi-bin/mapserv.exe?map="), port:mapPort);
  rcvRes = http_keepalive_send_recv(port:mapPort, data:sndReq, bodyonly:1);
  if("MapServer" >!< rcvRes){
    exit(0);
  }
}

mapVer = eregmatch(pattern:"MapServer version ([0-9]\.[0-9.]+)", string:rcvRes);
if(mapVer[1] != NULL)
{
  set_kb_item(name:"www/" + mapPort + "/MapServer", value:mapVer[1]);
  security_note(data:"MapServer version " + mapVer[1] + " was detected on the host");
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:mapVer[1], exp:"^([0-9.]+)", base:"cpe:/a:umn:mapserver:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
