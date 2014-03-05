##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_diagnostics_server_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# HP Diagnostics Server Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of HP Diagnostics Server

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802389";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-02-02 10:43:19 +0530 (Thu, 02 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("HP Diagnostics Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for HP Diagnostics Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


## HP Diagnostics Server port
hpdsPort = 2006;
if(!get_port_state(hpdsPort)){
  exit(0);
}

## Confirm the application
sndReq = http_get(item: "/", port:hpdsPort);
rcvRes = http_send_recv(port:hpdsPort, data:sndReq);

if (">HP Diagnostics" >< rcvRes && "Hewlett-Packard Development" >< rcvRes)
{
  hpdiagVer = eregmatch(pattern:">Server ([0-9.]+)", string:rcvRes);

  if(hpdiagVer[1])
  {
    ## Set HP Diagnostics Server Version in KB
    hpdiagVer = hpdiagVer[1];
    set_kb_item(name:"www/"+ hpdsPort + "/HP/Diagnostics_Server/Ver", value:hpdiagVer);
  }

  else{
   hpdiagVer = "unknown";
  }

  set_kb_item(name:"hpdiagnosticsserver/installed",value:TRUE);

  ## Build CPE
  cpe = build_cpe(value:hpdiagVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:diagnostics_server:");
  if(isnull(cpe))
    cpe = 'cpe:/a:hp:diagnostics_server';

  register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:hpdsPort);

  log_message(data:'Detected HP Diagnostics Server version: ' + hpdiagVer +
     '\nLocation: /' +
     '\nCPE: '+ cpe +
     '\n\nConcluded from version identification result:\n' +
     'HP Diagnostics Server '+ hpdiagVer, port:hpdsPort);
}
