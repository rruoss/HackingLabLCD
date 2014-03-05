###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbazar_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpBazar version detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "This script finds the running phpBazar version and saves
  the result in KB.";

if(description)
{
  script_id(800464);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("phpBazar version detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of phpBazar in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800464";
SCRIPT_DESC = "phpBazar version detection";

pbPort = get_http_port(default:80);
if(!pbPort){
  exit(0);
}

foreach path (make_list("/", "/phpBazar", "/PHPBazar", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:pbPort);
  rcvRes = http_send_recv(port:pbPort, data:sndReq);

  if("Welcome to phpBazar!" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/admin/admin.php"), port:pbPort);
    rcvRes = http_send_recv(port:pbPort, data:sndReq);

    if("phpBazar-AdminPanel" >< rcvRes)
    {
      pbVer = eregmatch(pattern:"phpBazar Ver. ([0-9.]+)", string:rcvRes);
      if(pbVer[1] != NULL){
        pbVer= pbVer[1];
      }
    }
    else
    {
      sndReq = http_get(item:string(path, "/classified.php"), port:pbPort);
      rcvRes = http_send_recv(port:pbPort, data:sndReq);

      if(!isnull(rcvRes))
      {
        pbVer = eregmatch(pattern:"phpBazar Ver. ([0-9.]+)", string:rcvRes);
        if(pbVer[1] != NULL){
          pbVer= pbVer[1];
        }
      }
    }

    tmp_version = pbVer + " under " + path;
    set_kb_item(name:"www/" + pbPort + "/phpBazar",
                value:tmp_version);
    security_note(data:"phpBazar version " + pbVer + " running at location " 
                    + path + " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:smartisoft:phpbazar:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
