###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Jetty Version Detection
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
tag_summary = "Detection of Jetty WebServer.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800953";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Jetty Version Detection");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Sets the KB for the version of Jetty");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

jettyPort = get_http_port(default:8080);
if(!jettyPort){
  jettyPort = 8080;
}

if(!get_port_state(jettyPort)){
  exit(0);
}

banner = get_http_banner(port:jettyPort);

if("Server: Jetty" >< banner)
{
  jettyVer = eregmatch(pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?",
                       string:banner);

  if(jettyVer[1] != NULL)
  {
    if(jettyVer[2] != NULL){
      jettyVer = jettyVer[1] + "." + jettyVer[2];
    }
    else
      jettyVer = jettyVer[1];

    set_kb_item(name:"www/" + jettyPort + "/Jetty", value:jettyVer);
    set_kb_item(name:"Jetty/installed", value:TRUE);

    cpe = build_cpe(value:jettyVer, exp:"^([0-9.]+)", base:"cpe:/a:mortbay:jetty:");
    if(!cpe)
      cpe = 'cpe:/a:mortbay:jetty';

    register_product(cpe:cpe, location:jettyPort + '/tcp', nvt:SCRIPT_OID, port:jettyPort);

    log_message(data: build_detection_report(app:"Jetty WebServer", version:jettyVer, install:jettyPort + '/tcp', cpe:cpe, concluded:version[0]),
                port:jettyPort);


  }
}
