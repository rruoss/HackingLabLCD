###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oraclebi_discoverer_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# OracleBI Discoverer Version Detection
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
tag_summary = "Detection of OracleBI Discoverer.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803130";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-19 10:33:12 +0530 (Wed, 19 Dec 2012)");
  script_name("OracleBI Discoverer Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of OracleBI Discoverer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
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
port = "";
dir = "";
url = "";
req = "";
res = "";
ver = "";
cpe  = "";

port = get_http_port(default:80);
if(!port){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

foreach dir (make_list("/", "/discoverer" , cgi_dirs()))
{
  url =  dir + "/viewer";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if(">OracleBI Discoverer" >< res && ">Oracle Technology" >< res)
 {

   set_kb_item(name:"OracleBI Discoverer/installed", value:TRUE);
   ver = eregmatch(string: res, pattern: "Version ([0-9.]+)");
   if(ver[1])
   {
     set_kb_item(name: string("www/", port, "/OracleBIDiscoverer"), value: string(ver[1]," under ",dir));
     set_kb_item(name:"OracleBIDiscoverer/installed", value:TRUE);

     ## build cpe and store it as host_detail
     cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:oracle:oraclebi_discoverer:");
     if(isnull(cpe))
       cpe = "cpe:/a:oracle:oraclebi_discoverer";

     register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);
     log_message(data: build_detection_report(app:"OracleBI Discoverer",
                                              version:ver[1],
                                              install:dir,
                                              cpe:cpe,
                                              concluded: ver[1]),
                                              port:port);

    }
  }
}
