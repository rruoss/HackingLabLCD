###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_machines_forum_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Simple Machines Forum Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of Simple Machines Forum
  and sets the result in KB.";

# Updated by Antu Sanadi <santu@secpod.com> on 2011-06-23
# - Updated to detect the recent versions
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

if(description)
{
  script_id(800557);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Simple Machines Forum Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of Simple Machines Forum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800557";
SCRIPT_DESC = "Simple Machines Forum Version Detection";

port = get_http_port(default:80);
if(!port){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

foreach dir (make_list("/smf", "/forum", "/board" , cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if("Powered by SMF" >< rcvRes || ">Simple Machines<" >< rcvRes)
  {
    version = eregmatch(pattern:"SMF ([0-9.]+).?(RC[0-9])?", string:rcvRes);
    if(version[1] != NULL)
    {
      if(version[2] == NULL){
        smfVer = version[1];
      }
      else{
        smfVer = version[1] + "." + version[2];
      }
    }

    if(!strlen(dir)){
      dir = "/";
    }

    tmp_version = smfVer + " under " + dir;
    set_kb_item(name:"www/" + port + "/SMF", value:tmp_version);
    security_note(port:port, data:"Simple Machines Forum version " + smfVer +
    " running at location " + dir + " was detected on the host");
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)(RC[0-9])?", base:"cpe:/a:simplemachines:smf:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
