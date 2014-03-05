##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_efront_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# eFront Version Detection
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
tag_summary = "This script detects the installed Efront version and sets
  the result in KB.";

if(description)
{
  script_id(901044);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("eFront Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_summary("Set KB for the version of eFront");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901044";
SCRIPT_DESC = "eFront Version Detection";

efrontPort = get_http_port(default:80);
if(!efrontPort){
  exit(0);
}

foreach dir (make_list("/efront", "/eFront", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/www/index.php"), port:efrontPort);
  rcvRes = http_send_recv(port:efrontPort, data:sndReq);

  if(("eFront" >< rcvRes) && ("Login" >< rcvRes))
  {
    efrontVer = eregmatch(pattern:"version ([0-9.]+)", string:rcvRes);
    if(efrontVer[1] != NULL){

      if(strlen(dir)<1) {
        dir = "/";
      }	

      tmp_version = efrontVer[1] + " under " + dir;
      set_kb_item(name:"www/"+ efrontPort + "/eFront",
                  value:tmp_version);
      security_note(data:"eFront version " + efrontVer[1] +
                 " running at location " + dir +  " was detected on the host");
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:efrontlearning:efront:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
