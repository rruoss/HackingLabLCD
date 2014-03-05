###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_event_horizon_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Event Horizon Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_summary = "This script finds the installed Event Horizon version and saves
  the result in KB.";

if(description)
{
  script_id(902081);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Event Horizon Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of Event Horizon in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

eventhPort = get_http_port(default:80);
if(!eventhPort){
  eventhPort = 80;
}

if(!get_port_state(eventhPort)){
  exit(0);
}

foreach dir (make_list("/eventhorizon", "/eventh", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:eventhPort);
  rcvRes = http_send_recv(port:eventhPort, data:sndReq);

  ## Confirm application is Event Horizon
  if(">Event Horizon<" >< rcvRes)
  {
    eventhVer = eregmatch(pattern:">Version ([0-9.]+)", string:rcvRes);
    if(isnull(eventhVer[1]))
    {
      ## Get the version from CHANGELOG
      sndReq = http_get(item:string(dir, "/CHANGELOG"), port:eventhPort);
      rcvRes = http_send_recv(port:eventhPort, data:sndReq);

      ## Grep for version
      ehVer = eregmatch(pattern:"([0-9.]+)", string:rcvRes);
      eventhVer = ehVer[1];
    }
    else
      eventhVer = eventhVer[1];

    ## Set the KB value
    set_kb_item(name:"www/" + eventhPort + "/Event/Horizon/Ver",
                      value:eventhVer + " under " + dir);
    security_note(data:"Event Horizon version " + eventhVer +
                       " running at location " + dir +
                       " was detected on the host", port:eventhPort);
  }
}
