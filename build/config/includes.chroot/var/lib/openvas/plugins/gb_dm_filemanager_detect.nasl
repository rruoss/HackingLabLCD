###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dm_filemanager_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# DM FileManager Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of DM FileManager and
  DM Albums and sets the result in KB.";

if(description)
{
  script_id(800818);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("DM FileManager Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of DM FileManager in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800818";
SCRIPT_DESC = "DM FileManager Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
dmfPort = get_http_port(default:80);
if(!dmfPort){
  dmfPort = 80;
}

if(!get_port_state(dmfPort)){
  exit(0);
}


foreach dir1 (make_list("/dm-filemanager", "/dmf", "/", cgi_dirs()))
{
  sndReq1 = http_get(item:string(dir1 + "/login.php"), port:dmfPort);
  rcvRes1 = http_send_recv(port:dmfPort, data:sndReq1);

  if(rcvRes1 =~ "<title>Log In - DM FileManager" &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes1))
  {
    dmfVer = eregmatch(pattern:"DM FileManager[^?]+v([0-9]\.[0-9.]+)",
                       string:rcvRes1);
    if(dmfVer[1] != NULL)
    {
      tmp_version = dmfVer[1] + " under " + dir1;
      set_kb_item(name:"www/" + dmfPort + "/DM-FileManager",
                  value:tmp_version);
      security_note(data:"DM FileManager version " + dmfVer[1] + " running at" + 
                         " location " + dir1 + " was detected on the host");

      ## build ccpe and store it as host detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:dutchmonkey:dm_filemanager:");
    }

    foreach dir2 (make_list("/dm-albums", "/albums"))
    {
      sndReq2 = http_get(item:dir1 + dir2 + "/readme.txt", port:dmfPort);
      rcvRes2 = http_send_recv(data:sndReq2, port:dmfPort);

      if("DM Albums" >< rcvRes2 &&
         egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2))
      {
        dmaVer = eregmatch(pattern:"Stable tag: ([0-9.]+)", string:rcvRes2);
        if(dmaVer[1] != NULL)
        {
          tmp_version = dmaVer[1] + " under " + dir2;
          set_kb_item(name:"www/" + dmfPort + "/DM-Albums",
                      value:tmp_version);
          security_note(data:"DM Albums version " + dmaVer[1] + " running at" + 
                         " location " + dir2 + " was detected on the host");

          ## build ccpe and store it as host detail
          register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:dutchmonkey:dm_album:");
        }
      }
    }
  }
}
