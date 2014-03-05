###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foswiki_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Foswiki Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "Detection of Foswiki.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800612";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"detection", value:"remote probe");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Foswiki Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of Foswiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialisation
cpe = "";
dir = "";
sndReq = "";
rcvRes = "";
install = "";
tmp_version ="";
foswikiPort = "";

foswikiPort = get_http_port(default:80);

if(!foswikiPort){
  foswikiPort = 80;
}

if(!get_port_state(foswikiPort)){
  exit(0);
}

foreach dir (make_list("", "/foswiki", "/wiki", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/Main/WebHome", port:foswikiPort);
  rcvRes = http_send_recv(port:foswikiPort, data:sndReq);

  if("Powered by Foswiki" >!< rcvRes){
    sndReq = http_get(item:dir + "/bin/view/foswiki/WebHome", port:foswikiPort);
    rcvRes = http_send_recv(port:foswikiPort, data:sndReq);
  }

  if(rcvRes =~ "HTTP/1\.[0-9]+ 200 OK" && "Powered by Foswiki" >< rcvRes )
  {
    if(strlen(dir)>0) {
      install=dir;
    } else {
      install=string("/");
    }

    foswikiVer = eregmatch(pattern:"Foswiki-([0-9.]+),", string:rcvRes);
    if(isnull(foswikiVer[1])){
       foswikiVer[0] = "Foswiki unknown";
       foswikiVer[1] = "unknown";
    }

    tmp_version = foswikiVer[1] + " under " + install;

    set_kb_item(name: string("www/", foswikiPort, "/Foswiki"), value: tmp_version);
    set_kb_item(name:"Foswiki/installed", value:TRUE);

    cpe = build_cpe(value:foswikiVer[1], exp:"^([0-9.]+)", base:"cpe:/a:foswiki:foswiki:");
    if(isnull(cpe))
      cpe = 'cpe:/a:foswiki:foswiki';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:foswikiPort);

    log_message(data: build_detection_report(app:"Foswiki", version:foswikiVer[1], install:install, cpe:cpe, concluded:foswikiVer[0]), port:foswikiPort);
  }
}
