###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# WampServer Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_summary = "This script finds the installed WampServer version and
  saves the result in KB.";

if(description)
{
  script_id(800297);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("WampServer Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of WampServer in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800297";
SCRIPT_DESC = "WampServer Version Detection";

wampPort = get_http_port(default:80);
if(!wampPort){
  wampPort = 80;
}

if(get_port_state(wampPort))
{
  sndReq = http_get(item: "/index.php", port:wampPort);
  rcvRes = http_keepalive_send_recv(port:wampPort, data:sndReq);
  if("WampServer" >< rcvRes)
  {
    wampVer = eregmatch(pattern:">[vV]ersion ([0-9.a-z]+)" , string:rcvRes);
    if(wampVer[1] != NULL){
      set_kb_item(name:"www/" + wampPort + "/WampServer",value:wampVer[1]);
      security_note(data:"WampServer version " + wampVer[1] +
                         " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:wampVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wampserver:wampserver:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
