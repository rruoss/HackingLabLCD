###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Sun Java System Web Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By Veerendra G <veerendragg@secpod.com>
# date update: 2010/01/20
# Added for loop to check for all the ports (80, 8800, 8989, 8888)
#
# Updated By Sooraj KS <kssooraj@secpod.com>
# date update: 2012/07/03
# Updated to detect Oracle iPlanet Web Server
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
tag_summary = "Detection of Sun Java System Web Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800810";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Sun Java System Web Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of Sun Java System Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80, 8800, 8989, 8888);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("openvas-https.inc");

vers = "";
body = "";
banner = "";
jswsPort = 0;
version = NULL;
jswsVer = NULL;

app = "Sun Java System Web Server";

foreach jswsPort (make_list(80, 8800, 8989, 8888))
{
  if(get_port_state(jswsPort))
  {
    banner = get_http_banner(port:jswsPort);
    if(banner)
    {
      if("Server: Sun-" >< banner || "Server: Oracle-iPlanet-Web-Server" >< banner)
      {
	url = "/admingui/version/copyright";
	req = http_get(item:url, port:jswsPort);
	body = http_send_recv(port: jswsPort, data: req);

	if("Location: https://" >< body) {
	  body = https_req_get(port:jswsPort, request: req);
	}

        if("Sun Java System Web Server" >< body)
        {
          version = eregmatch(pattern: "Sun Java System Web Server ([^ ]+)", string: body);

          cpe = build_cpe(value:vers, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_web_server:");
          if(isnull(cpe))
            cpe = 'cpe:/a:sun:java_system_web_server';
        }

        else if("Oracle iPlanet Web Server" >< body)
        {
          app = "Oracle iPlanet Web Server";
          version = eregmatch(pattern: "Oracle iPlanet Web Server ([0-9.]+)", string: body);

          cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:sun:iplanet_web_server:");
          if(isnull(cpe))
            cpe = 'cpe:/a:sun:iplanet_web_server';
        }

	if(!isnull(version[1]))
        {
          set_kb_item(name:string("Sun/JavaSysWebServ/",jswsPort,"/Ver"),value: version[1]);
          vers = version[1];
	}
      

        jswsVer = eregmatch(pattern:"Server: Sun-(ONE|Java-System)-Web-Server\/" +
                                    "([0-9]\.[0-9.]+)([^0-9.]|$)",
                            string:banner);
        if(jswsVer[2] != NULL)
        {
          set_kb_item(name:"Sun/JavaSysWebServ/Ver", value:jswsVer[2]);
          set_kb_item(name:"Sun/JavaSysWebServ/Port", value:jswsPort);
          vers = jswsVer[2];

          cpe = build_cpe(value:vers, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_web_server:");
          if(isnull(cpe))
            cpe = 'cpe:/a:sun:java_system_web_server';
        }

        register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:jswsPort);

        set_kb_item(name:"java_system_web_server/installed",value:TRUE);

        log_message(data: build_detection_report(app:app, version:vers,
                    install:"/", cpe:cpe, concluded: vers), port:jswsPort);
      }  
    }
  }
}
