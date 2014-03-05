###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tembria_server_monitor_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Tembria Server Monitor Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-29
# -updated to detect the build number
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the Tembria Server Monitor version and
  saves the result in KB.";

if(description)
{
  script_id(901107);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Tembria Server Monitor Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Tembria Server Monitor in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901107";
SCRIPT_DESC = "Tembria Server Monitor Version Detection";

## Get Tembria Server Monitor Port
port = get_http_port(default:8080);
if(!port){
 exit(0);
}

foreach dir (make_list("/", "/tembria", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if('>Tembria Server Monitor<' >< res)
  {
    ## Get Tembria Server Monitor Version
    ver = eregmatch(pattern:"<version>v([0-9\.]+)</version>", string:res);
    if(ver[1])
    {
      bver = eregmatch(pattern:"<buildno>([0-9.]+)</buildno>", string:res);
      if(bver[1]){
        version = ver[1] + "." +bver[1];
      }
      else {
        version = ver[1];
      }
    }

    ## Set Tembria Server Monitor Version in KB
    tmp_version = version + " under " + dir;
    set_kb_item(name:"www/" + port + "/tembria", value:tmp_version);
    security_note(data:"Tembria Server Monitor version " + version +
              " running at location " + dir + " was detected on the host");
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:tembria:server_monitor:");
  if(!isnull(cpe)){
    register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  }
}
