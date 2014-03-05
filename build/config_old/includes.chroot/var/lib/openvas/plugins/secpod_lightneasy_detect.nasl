##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lightneasy_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# LightNEasy Version Detection
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
tag_summary = "This script detects the installed version of LightNEasy and
  sets the result in KB.";

if(description)
{
  script_id(900371);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("LightNEasy Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of LightNEasy");
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
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900371";
SCRIPT_DESC = "LightNEasy Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
lightNEasyPort = get_http_port(default:80);
if(!lightNEasyPort){
  lightNEasyPort = 80;
}

if(!get_port_state(lightNEasyPort)){
  exit(0);
}

foreach lightDir (make_list("/lightneasy", "/nodatabase", "/sqlite", "/",
                  cgi_dirs()))
{
  sndReq = http_get(item:string(lightDir, "/LightNEasy.php?do=login"),
                    port:lightNEasyPort);
  rcvRes = http_send_recv(port:lightNEasyPort, data:sndReq);

  if("LightNEasy" >!< rcvRes || rcvRes == NULL)
  {
    sndReq = http_get(item:string(lightDir, "/index.php"), port:lightNEasyPort);
    rcvRes = http_send_recv(port:lightNEasyPort, data:sndReq);
  }

  if("LightNEasy" >< rcvRes && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    lightNEasyVer = eregmatch(pattern:"LightNEasy ([0-9.]+)", string:rcvRes);
    if("SQLite" >< rcvRes || "sqlite" >< rcvRes)
    {
      if(lightNEasyVer[1]!= NULL)
      {
        tmp_version = lightNEasyVer[1] + " under " + lightDir;
        set_kb_item(name:"www/"+ lightNEasyPort + "/LightNEasy/Sqlite",
                    value:tmp_version);
        security_note(data:"LightNEasy version " + lightNEasyVer[1] +
            " running at location " + lightDir +  " was detected on the host");

        ## build cpe and store it as host detail
        register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:sqlite:sqlite:");

      }
    }
    else if(lightNEasyVer[1] != NULL)
    {
      tmp_version = lightNEasyVer[1] + " under " + lightDir;
      set_kb_item(name:"www/"+ lightNEasyPort + "/LightNEasy/NoDB",
                  value:tmp_version);
      security_note(data:"LightNEasy version " + lightNEasyVer[1] + 
            " running at location " + lightDir +  " was detected on the host");

      ## build cpe and store it as host detail
      register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:lightneasy:lightneasy:");
    }
  }
}
