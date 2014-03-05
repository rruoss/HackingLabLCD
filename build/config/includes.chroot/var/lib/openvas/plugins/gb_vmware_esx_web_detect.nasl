###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esx_web_detect.nasl 65 2013-11-14 11:18:55Z mime $
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
tag_summary = "This host is running VMware ESX(i).";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103418";

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 65 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-14 12:18:55 +0100 (Do, 14. Nov 2013) $");
 script_tag(name:"creation_date", value:"2012-02-14 11:30:38 +0100 (Tue, 14 Feb 2012)");
 script_name("VMware ESX detection (Web)");

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Checks for the presence of VMware ESX (Web)");
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

SCRIPT_DESC = "VMware ESX detection (Web)";

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

if("VMware ESX" >!< buf && "ID_EESX_Welcome" >!< buf)exit(0); 

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

if("RetrieveServiceContentResponse" >< buf) {

  if("<fullName>VMware vCenter" >< buf)exit(0);

  if("ESXi" >< buf) {
    typ = "ESXi";
  }

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
     replace_kb_item(name:"VMware/ESX/build", value:build[1]); 
     build =  build[1];
    }
  }

  r = eregmatch(pattern:"<returnval>(.*)</returnval>", string:buf);
  if(!isnull(r[1])) {
    rs = r[1];
  }

} 

close(soc);

if("ESXi" >< typ) {
  cpe_string = "cpe:/o:vmware:esxi";
  set_kb_item(name:"VMware/ESX/typ/ESXi",value:TRUE); # ESXi
} else {
  cpe_string = "cpe:/o:vmware:esx";
  set_kb_item(name:"VMware/ESX/typ/ESXs",value:TRUE); # ESX Server
}

if(vers != "unknown") {
 cpe = build_cpe(value:vers, exp:"^([0-9.a-z]+)", base:cpe_string + ":");
} else {
 cpe = cpe_string; 
}

register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
register_host_detail(name:"OS", value:"VMware ESX(i)", nvt:SCRIPT_OID, desc:SCRIPT_DESC);

set_kb_item(name:"VMware/GSX-Server/web/version",value:vers);
set_kb_item(name:"VMware/ESX/version",value:vers);
set_kb_item(name:"VMware/ESX/installed",value:TRUE);
set_kb_item(name:"VMware/ESX/port",value:port);

result_txt = 'Detected ' + typ  + ' Version: ';
result_txt += vers;

if(build) {
  result_txt += " Build " + build;
}

result_txt += '\nCPE: '+ cpe;
result_txt += '\n\nConcluded from remote probe';

if(rs) {
  result_txt += ':\n' + rs + '\n';
}

result_txt += '\n';

log_message(port:port, data:result_txt);

exit(0);
