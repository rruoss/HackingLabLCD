###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vcenter_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# VMware ESX detection (Web)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "This host is running VMware vCenter.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103659";

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-06 17:30:38 +0100 (Wed, 06 Feb 2013)");
 script_name("VMware vCenter detection (Web)");

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Checks for the presence of VMware vCenter (Web)");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("services/www",443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.vmware.com");
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default:443);
transport = get_port_transport(port);

if(!get_port_state(port)) {
  exit(0);
}  

soc = open_sock_tcp(port, transport: transport);
if(!soc) {
  exit(0);
}  

host = get_host_name();

req  = string("GET / HTTP/1.1\r\n");
req += string("Host: ",get_host_name(),":",port,"\r\n\r\n");

send(socket: soc, data: req);
buf = recv(socket:soc, length:8192);

if("VMware" >!< buf)exit(0); 

close(soc); # neeeded for the strange behaviour of esx 3.x
soc = open_sock_tcp(port, transport: transport);
if(!soc)exit(0);

vers = "unknown";

req  = string("POST /sdk HTTP/1.1\r\n");
req += string("Host: ",get_host_name(),":",port,"\r\n");
req += string("Content-Type: application/x-www-form-urlencoded\r\n");
req += string("Content-Length: 348\r\n\r\n");
req += string('
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
\t\t\t<env:Body>
\t\t\t<RetrieveServiceContent xmlns="urn:vim25">
\t\t\t\t<_this type="ServiceInstance">ServiceInstance</_this>
\t\t\t</RetrieveServiceContent>
\t\t\t</env:Body>
</env:Envelope>');
req += string("\r\n");

send(socket: soc, data: req);
buf = recv(socket:soc, length:8192);

if("RetrieveServiceContentResponse" >!< buf)exit(0);
if("<fullName>VMware vCenter Server" >!< buf)exit(0);

version = eregmatch(pattern:"<version>([0-9.]+)</version>", string:buf);
if(!isnull(version[1])) {
  vers = version[1];
}

name = eregmatch(pattern:"<name>(.*)</name>", string:buf);
if(!isnull(name[1])) {
  typ = name[1];
}

if("<build>" >< buf) {
  build = eregmatch(pattern:"<build>([0-9]+)</build>", string:buf);
  if(!isnull(build[1])) {
   build =  build[1];
  }
}

r = eregmatch(pattern:"<returnval>(.*)</returnval>", string:buf);
if(!isnull(r[1])) {
  rs = r[1];
}


close(soc);

cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vcenter:");
if(isnull(cpe))
  cpe = 'cpe:/a:vmware:vcenter';

register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

set_kb_item(name:"VMware_vCenter/installed", value:TRUE);
set_kb_item(name:"VMware_vCenter/" + port + "/version", value: vers);
set_kb_item(name:"VMware_vCenter/" + port + "/build", value: build);

log_message(data: build_detection_report(app:"VMware vCenter Server", version:vers, install:port + '/tcp', cpe:cpe, concluded: rs),
            port:port);

exit(0);
