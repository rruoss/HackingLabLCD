###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Ruby on Rails Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 2011-07-05
#    -Modified the regex for detecting beta versions.
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
tag_summary = "This script finds the running Ruby on Rails version and
  saves the result in KB.";

if(description)
{
  script_id(902089);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_name("Ruby on Rails Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Ruby on Rails in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get Rby on Rails
rorPort = "3000";

if(!get_port_state(rorPort)){
  exit(0);
}

## Send and Recieve the respose
sndReq = http_get(item:"/", port:rorPort);
rcvRes = http_keepalive_send_recv(port:rorPort, data:sndReq);

## Confirm it is Rails on Rails
if(">Ruby on Rails" >< rcvRes)
{
  sndReq = http_get(item:string("/rails/info/properties/"), port:rorPort);
  rcvRes = http_keepalive_send_recv(port:rorPort, data:sndReq);

  ## Grep the version
  rorVer = eregmatch(pattern:">Rails version.*([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rcvRes);
  if(rorVer[0] != NULL)
  {
    rorVer = eregmatch(pattern:">([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rorVer[0]);
    if(rorVer[1] != NULL)
    {
      if(rorVer[3] != NULL)
      {
        set_kb_item(name:"www/" + rorPort + "/Ruby/Rails/Ver", value:rorVer[1] +
                                                            rorVer[2]);
        security_note(data:"Ruby on Rails version " + rorVer[1] + rorVer[2] +
                         " was detected on the host", port:rorPort);
      }
      else
      {
        set_kb_item(name:"www/" + rorPort + "/Ruby/Rails/Ver", value:rorVer[1]);
        security_note(data:"Ruby on Rails version " + rorVer[1] +
                 " was detected on the host", port:rorPort);

      }
    }
  }
}

