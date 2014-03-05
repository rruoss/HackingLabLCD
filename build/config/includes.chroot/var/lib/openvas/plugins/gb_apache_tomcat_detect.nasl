##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Apache Tomcat Version Detection
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
tag_summary = "Detection of Apache Tomcat.
                     
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800371";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Apache Tomcat Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the Version of Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

if(!get_port_state(port)){
  exit(0);
}

sndReq = http_get(item:string("/index.jsp \r\n"), port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if(rcvRes == NULL || "Tomcat" >!< rcvRes)
{
  sndReq = http_get(item:string("/RELEASE-NOTES.txt \r\n"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(rcvRes == NULL || "Tomcat" >!< rcvRes) {

    sndReq = http_get(item:string("/i_dont_exist \r\n"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(rcvRes == NULL || "Tomcat" >!< rcvRes)exit(0);

  }
}

tomcatVer = eregmatch(pattern:"Apache Tomcat( Version |\/)([0-9.]+)",
                      string:rcvRes);

if("Apache Tomcat" >< tomcatVer[0] && tomcatVer[2] != NULL)
{
  set_kb_item(name:"www/" + port + "/ApacheTomcat", value:tomcatVer[2]);
  set_kb_item(name:"ApacheTomcat/installed", value:TRUE);

  cpe = build_cpe(value:tomcatVer[2], exp:"^([0-9.]+)", base:"cpe:/a:apache:tomcat:");
  if(isnull(cpe))
    cpe = 'cpe:/a:apache:tomcat';

  register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);
  log_message(data: build_detection_report(app:"Apache Tomcat", version:tomcatVer[2], install:port + '/tcp', cpe:cpe, concluded: tomcatVer[0]),
              port:port);
}
