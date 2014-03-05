###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_appserv_open_project_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# AppServ Open Project Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of AppServ Open Project, a open source web
  server (http://www.appservnetwork.com/?appserv).

The script sends a connection request to the web server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802428";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-16 13:02:43 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Checks for the presence of AppServ Open Project and set version in KB");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Variables Initialization
port  = 0;
appVer = "";
banner = "";
sndReq = "";
rcvRes = "";
cpe    = "";
location = "";

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Send the request and  confirm the response
sndReq = http_get(item: "/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm AppServ Open Project
if("title>AppServ Open Project" >< rcvRes && ">About AppServ" >< rcvRes)
{
  ## Grep for the version
  appVer = eregmatch(pattern:"AppServ Version ([0-9.]+)" , string:rcvRes);
  if(appVer[1] != NULL)
  {
    ## Set the version
    set_kb_item(name:"www/" + port + "/AppServ",value:appVer[1]);
    set_kb_item(name:"AppServ/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:appVer[1], exp:"^([0-9.]+)",
                      base:" cpe:/a:appserv_open_project:appserv:");
    if(isnull(cpe))
      cpe = 'cpe:/a:appserv_open_project:appserv';

    location = string(port, "/http");
    register_product(cpe:cpe, location:location, nvt:SCRIPT_OID, port:port);

    log_message(data:'Detected AppServ Open Project version: ' + appVer[1] +
    '\nLocation: ' + location +
    '\nCPE: '+ cpe +
    '\n\nConcluded from version identification result:\n'
    + appVer[max_index(appVer)-1]);
  }
}
