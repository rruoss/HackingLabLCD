###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Limny Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of Limny.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800295";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Limny Version Detection");
  script_tag(name:"detection", value:"remote probe");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Limny in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
limPort = "";
dir = "";
sndReq = "";
rcvRes = "";
limVer = "";
tmp_version = "";
cpe = "";

limPort = get_http_port(default:80);
if(!limPort){
  limPort = 80;
}

if(!get_port_state(limPort)){
  exit(0);
}

foreach dir (make_list("", "/limny", "/limny/upload", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:limPort);
  rcvRes = http_send_recv(port:limPort, data:sndReq);
  if("Limny" >< rcvRes)
  {
    limVer = eregmatch(pattern:"Limny ([0-9.]+)" , string:rcvRes);
    if(limVer[1] != NULL)
    {
       tmp_version = limVer[1] + " under " + dir;
       set_kb_item(name:"www/" + limPort + "/Limny", value:tmp_version);
       set_kb_item(name:"limny/installed",value:TRUE);

       security_note(data:"Limny version " + limVer[1] + " running at location "
                    + dir + " was detected on the host");

       cpe = build_cpe(value:limVer[1], exp:"^([0-9.]+)", base:"cpe:/a:limny:limny:");
       if(!cpe)
          cpe = 'cpe:/a:limny:limny';

       register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:limPort);

       log_message(data: build_detection_report(app:"Limny", version:limVer[1],
                                                install:dir, cpe:cpe,
                                                concluded: dump[max_index(dump)-1]),
                                                port:limPort);

    }
  }
}
