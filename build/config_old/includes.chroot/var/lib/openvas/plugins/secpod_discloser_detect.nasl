###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_discloser_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Discloser Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) SecPod, http://www.secpod.com
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
tag_summary = "This script finds the running Discloser and saves the
  result in KB.";

if(description)
{
  script_id(902137);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_name("Discloser Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Discloser in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902137";
SCRIPT_DESC = "Discloser Version Detection";

discPort = get_http_port(default:80);
if(!discPort){
  exit(0);
}

foreach path (make_list("/discloser", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/login.php"), port:discPort);
  rcvRes = http_send_recv(port:discPort, data:sndReq);

  if("discloser admin" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/CHANGELOG"), port:discPort);
    rcvRes = http_send_recv(port:discPort, data:sndReq);

    discVer = eregmatch(pattern:"Version (([0-9.]+).?([a-zA-z0-9]+)?)", string:rcvRes);
    if(isnull(discVer[1]))
    {
      sndReq = http_get(item:string(path, "/docs/CHANGELOG"), port:discPort);
      rcvRes = http_send_recv(port:discPort, data:sndReq);

      discVer = eregmatch(pattern:"Version (([0-9.]+).?([a-zA-z0-9]+)?)", string:rcvRes);
      if(!isnull(discVer)){
        discVer = discVer;
      }
    }

    if(discVer[1])
    {
        tmp_version = discVer + " under " + path;
        discVer = ereg_replace(pattern:"-", string:discVer[1], replace:".");
        set_kb_item(name:"www/" + discPort + "/Discloser",
                value:tmp_version);
        security_note(data:"Discloser version " + discVer +
               " running at location " + path +  " was detected on the host");
      
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:bob_jewell:discloser:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
