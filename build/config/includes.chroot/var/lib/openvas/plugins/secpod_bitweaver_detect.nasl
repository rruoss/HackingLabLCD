##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitweaver_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Bitweaver Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Bitweaver and
  sets the result in KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900355";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Bitweaver Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of Bitweaver");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

bitweaverPort = get_http_port(default:80);
if(!bitweaverPort){
  bitweaverPort = 80;
}

if(!get_port_state(bitweaverPort)){
  exit(0);
}

foreach dir (make_list("/bitweaver", "/bw", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/wiki/index.php"), port:bitweaverPort);
  rcvRes = http_send_recv(port:bitweaverPort, data:sndReq);

  if("Powered by bitweaver" >!< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/users/login.php"), port:bitweaverPort);
    rcvRes = http_send_recv(port:bitweaverPort, data:sndReq);
  }

  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
     "Powered by bitweaver" >< rcvRes)
  {
    bitweaverVer = eregmatch(pattern:"Version: (<strong>)?([0-9]\.[0-9.]+)",
                             string:rcvRes);
    if(bitweaverVer[2] != NULL)
    {
      tmp_version = bitweaverVer[2] + " under " + dir;
      set_kb_item(name:"www/"+ bitweaverPort + "/Bitweaver", value:tmp_version);
      set_kb_item(name:"Bitweaver/installed", value:TRUE);
  
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:bitweaver:bitweaver:");
      if(isnull(cpe))
        cpe = 'cpe:/a:bitweaver:bitweaver';

      register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:bitweaverPort);

      log_message(data: build_detection_report(app:"Bitweaver", version:bitweaverVer[2], install:dir, cpe:cpe, concluded: bitweaverVer[0]),
                  port:bitweaverPort);

    }
  }
}
