###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfire_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenFire Version Detection
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
tag_summary = "This script detects the installed version of OpenFire and
  sets the result in KB.";

if(description)
{
  script_id(800353);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("OpenFire Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of OpenFire");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800353";
SCRIPT_DESC = "OpenFire Version Detection";

# Check for default port 9090
firePort = get_http_port(default:9090);
if(!firePort){
  firePort = 9090;
}

if(get_port_state(firePort))
{
  sndReq = string("GET /login.jsp:", "\r\n",
                  "Host: ", get_host_name(), ":", firePort , "\r\n");
  rcvRes = http_keepalive_send_recv(port:firePort, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if("Openfire Admin Console" >< rcvRes)
  {
    fireVer = eregmatch(pattern:"Openfire, Version: ([0-9.]+)", string:rcvRes);
    if(fireVer[1] != NULL)
    {
      set_kb_item(name:"www/" + firePort + "/Openfire", value:fireVer[1]);
      security_note(data:"OpenFire version " + fireVer[1] +
                   " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:fireVer[1], exp:"^([0-9.]+)", base:"cpe:/a:igniterealtime:openfire:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
