###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simpleid_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# SimpleID Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the running SimpleID version and
  saves the result in KB.";

if(description)
{
  script_id(801415);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_name("SimpleID Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of SimpleID in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801415";
SCRIPT_DESC = "SimpleID Version Detection";

## Get HTTP Port
simidPort = get_http_port(default:80);
if(!get_port_state(simidPort)){
  exit(0);
}

foreach path (make_list("/simpleid", "/SimpleID", "/", cgi_dirs()))
{
  ## Send and Recieve the respose
  sndReq = http_get(item:string(path, "/www/index.php"), port:simidPort);
  rcvRes = http_send_recv(port:simidPort, data:sndReq);

  ## Confirm it is SimpleID
  if(">SimpleID<" >< rcvRes)
  {
    ## Grep the version
    simidVer = eregmatch(pattern:"SimpleID ([0-9.]+)", string:rcvRes);
    if(simidVer[1] != NULL)
    {
      ## Set the KB item
      tmp_version = simidVer[1] + " under " + path;
      set_kb_item(name:"www/" + simidPort + "/SimpleID/Ver", value:tmp_version);
      security_note(data:"SimpleID version " + simidVer[1] +
                         " running at location " + path +
                         " was detected on the host", port:simidPort);
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:kelvin_mo:simpleid:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
