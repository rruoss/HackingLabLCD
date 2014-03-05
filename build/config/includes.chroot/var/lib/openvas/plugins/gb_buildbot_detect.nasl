###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buildbot_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Buildbot Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script detects the installed version of Buildbot
  and sets the result in KB.";

if(description)
{
  script_id(800933);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Buildbot Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Buildbot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8010);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800933";
SCRIPT_DESC = "Buildbot Version Detection";

buildbotPort = get_http_port(default:8010);
if(!buildbotPort){
  buildbotPort = 8010;
}

if(!get_port_state(buildbotPort)){
  exit(0);
}

foreach dir (make_list("/", "/buildbot", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/about", port:buildbotPort);
  rcvRes = http_send_recv(port:buildbotPort, data:sndReq);

  if("Buildbot" >< rcvRes)
  {
    buildbotVer = eregmatch(pattern:"Buildbot.?.?(([0-9.]+)([a-z][0-9]+)?)",
                            string:rcvRes);

    if(!isnull(buildbotVer[2]))
    {
      if(!isnull(buildbotVer[3]))
        buildbotVer = buildbotVer[2] + "." + buildbotVer[3];
      else
        buildbotVer = buildbotVer[2];
      set_kb_item(name:"Buildbot/Ver", value:buildbotVer);
      security_note(data:"Build bot version " + buildbotVer + " running at" + 
                         " location " + dir + " was detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:builbotVer, exp:"^([0-9.]+\.[0-9])([a-z][0-9]+)?", base:"cpe:/a:buildbot:buildbot:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
