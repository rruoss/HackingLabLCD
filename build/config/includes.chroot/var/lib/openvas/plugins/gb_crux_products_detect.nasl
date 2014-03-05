###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_crux_products_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# CruxSoftware Products Version Detection
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
tag_summary = "This script finds the running CruxSoftware Products version and
  saves the result in KB.";

if(description)
{
  script_id(801381);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("CruxSoftware Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of CruxSoftware Products in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("CruxSoftware Products Version Detection");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801381";
SCRIPT_DESC = "CruxSoftware Products Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
cmsPort = get_http_port(default:80);
if(!cmsPort){
  cmsPort = 80;
}

if(!get_port_state(cmsPort)){
  exit(0);
}

## For CruxCMS
foreach dir (make_list("/CruxCMS", "/CruxCMS300/manager", "/cms","/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/login.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  if("404 Not Found" >< rcvRes) {
    sndReq = http_get(item:string(dir , "/index.php"), port:cmsPort);
    rcvRes = http_send_recv(port:cmsPort, data:sndReq);
  }  

  if(">Crux CMS<" >< rcvRes)
  {
    foreach filename (make_list("/../Docs/ReadMe.txt", "/../Docs/ChangeLog.txt",
                                "/Docs/ChangeLog.txt", "/Docs/ReadMe.txt"))
    {
       sndReq = http_get(item:string(dir , filename), port:cmsPort);
       rcvRes = http_send_recv(port:cmsPort, data:sndReq);
       if("CruxCMS" >< rcvRes)
       {
         cmsVer = eregmatch(pattern:"Version ([0-9.]+)", string:rcvRes);
         if(cmsVer[1] != NULL)
         {
           tmp_version = cmsVer[1] + " under " + dir;
           set_kb_item(name:"www/" + cmsPort + "/CruxCMS", value:tmp_version);
           security_note(data:"CruxCMS version " + cmsVer[1] + " running at location "
                         + dir + " was detected on the host");

           ## build cpe and store it as host_detail
           register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:cruxsoftware:cruxcms:");

	   break;
         }
       }
     }
   }
}

## For CruxPA
foreach dir (make_list("/CruxPA200", "/CruxPA200/Manager", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/login.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);
  if("CruxPA" >< rcvRes)
  {
    foreach filename (make_list("/../Docs/ReadMe.txt", "/../Docs/ChangeLog.txt",
                                "/Docs/ChangeLog.txt", "/Docs/ReadMe.txt"))
    {
      sndReq = http_get(item:string(dir , filename), port:cmsPort);
      rcvRes = http_send_recv(port:cmsPort, data:sndReq);
      if("CruxPA" >< rcvRes)
      {
        cmspaVer = eregmatch(pattern:"Version ([0-9.]+)", string:rcvRes);
        if(cmspaVer[1] != NULL)
        {
          tmp_version = cmspaVer[1] + " under " + dir;
          set_kb_item(name:"www/" + cmsPort + "/CruxPA", value:tmp_version);
          security_note(data:"CruxPA version " + cmspaVer[1] + " running at location "
                         + dir + " was detected on the host");

          ## build cpe and store it as host_detail
          register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:cruxsoftware:cruxpa:");

	  break;
        }
      }
    }
  }
}
