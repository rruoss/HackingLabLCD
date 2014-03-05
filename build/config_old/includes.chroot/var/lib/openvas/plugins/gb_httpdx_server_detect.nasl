###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_server_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# httpdx Server Version Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of httpdx Server.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800960";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("httpdx Server Version Detection");
  script_tag(name:"detection", value:"remote probe");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Checks for the presence of httpdx");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", "Services/ftp", 80, 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("ftp_func.inc");
include("http_func.inc");
include("host_details.inc");

## Variable Initialization
ftpPort = 0;
httpPort = 0;
banner = "";
httpdxVer = NULL;
vers = string("unknown");

httpPort = get_kb_item("Services/www");
if(!httpPort){
  httpPort = 80;
}

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

foreach port (make_list(httpPort, ftpPort))
{
  if(get_port_state(port))
  {
    banner = get_http_banner(port:port);
    if("httpdx" >!< banner){
      banner = get_kb_item(string("Banner/", port));
    }

    if(banner && "httpdx" >< banner)
    {
      httpdxVer = eregmatch(pattern:"httpdx.([0-9.]+[a-z]?)", string:banner);
      if(!isnull(httpdxVer[1]))
      {
        set_kb_item(name:"httpdx/" + port + "/Ver", value:httpdxVer[1]);
        vers = httpdxVer[1];
      }

      set_kb_item(name:"httpdx/installed", value:TRUE);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:vers, exp:"^([0-9.]+([a-z]+)?)", base:"cpe:/a:jasper:httpdx:");
      if(isnull(cpe))
        cpe = 'cpe:/a:jasper:httpdx';

      register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

      log_message(data: build_detection_report(app:"httpdx", version:vers,
                  install:"/", cpe:cpe, concluded: vers), port:port);
    }
  }
}
