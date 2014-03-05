###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Apache Traffic Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Tim Brown <timb@openvas.org>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-03-29
# - Updated to set KB if Traffic Server is installed and grep all versions
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Detection of Apache Traffic Server, a open source web
 server (http://trafficserver.apache.org/).

The script sends a connection request to the web server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100796";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
 script_name("Apache Traffic Server Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Apache Traffic Server");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_require_ports("Services/http_proxy", 8080,3128,80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Variables Initialization
port  = 0;
dir  = "";
ver  = "";
version = "";
banner = "";
dump   = "";
cpe    = "";
tmp_version = "";

port = get_kb_item("Services/http_proxy");
if(!port)port = 8080;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || ("Server: ATS/" >!< banner && "ApacheTrafficServer" >!<  banner))exit(0);

version = eregmatch(pattern:"Server: ATS/([0-9.]+)",string:banner);
dir = "/";
dump = version;

if(version[1]){
  ver = version[1];
}

## Set the KB value
set_kb_item(name:"www/" + port + "/apache_traffic_server", value:ver);
set_kb_item(name:"apache_trafficserver/installed",value:TRUE);

## build cpe and store it as host_detail
cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:apache:traffic_server:");

if(isnull(cpe))
  cpe = 'cpe:/a:apache:traffic_server';

register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port: port);

log_message(data:'Detected Apache Traffice Grapher version: ' + ver +
  '\nLocation: ' + dir +
  '\nCPE: '+ cpe +
  '\n\nConcluded from version identification result:\n' + dump[max_index(dump)-1]);

exit(0);
