###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Memcached Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "Detection of Memcached.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800714";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Memcached Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of MemcacheDB in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports(11211);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

# Port used by Memcached Daemon
port = 11211;
appsock = "";
response = "";
version = "";

if(!get_port_state(port)){
  exit(0);
}

data = string("version \r\n");
appsock = open_sock_tcp(port);
if(!appsock){
  exit(0);
}

send(socket:appsock, data:data);
response = recv(socket:appsock, length:1024);
close(appsock);

if(!response){
  exit(0);
}

version = eregmatch(pattern:"VERSION ([0-9.]+)", string:response);
if(version[1] != NULL)
{
  set_kb_item(name:"MemCached/installed", value:TRUE);
  set_kb_item(name:"MemCached/Ver", value:version[1]);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:memcachedb:memcached:");
  if(isnull(cpe))
    cpe = 'cpe:/a:memcachedb:memcached';

  register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"MemCached", version:version[1], install:"/",
            cpe:cpe, concluded:version[1]), port:port);

}
