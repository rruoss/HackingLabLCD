###############################################################################
# OpenVAS Vulnerability Test
# $Id: nagios_statd_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Nagios-statd Daemon Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Nagios-statd Daemon is running at this port.

  Nagios-statd (nagios-statd  Daemon)  is the daemon program for
  nagios-stat.  These programs together comprise a  systems monitoring
  tool for various platforms.  It is designed to be integrated with the
  Nagios monitoring tool, although this is not a requirement.

  Nagios-statd is the daemon that listens for connections  from
  clients.  It  forks  off  a  new daemon for each incoming connection.
  The forked daemon executes a series of typical UNIX  commands  and
  returns  those commands standard output to the client.";

tag_solution = "Limit incoming traffic to this port.";

# need desc here to modify it later in script.
desc = "
 
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description)
{
 script_id(100187);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Nagios-statd Daemon Detection");  

 script_description(desc);
 script_summary("Checks for the presence of Nagios-statd Daemon");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 1040);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("misc_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100187";
SCRIPT_DESC = "Nagios-statd Daemon Detection";

port = 1040;

if (known_service(port:port))exit(0);
if(!get_tcp_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
  
req = string("version\r\n");
send(socket:soc, data:req);
while (data = recv_line(socket:soc, length:100)) {
   ret += data;
}    
  

if("nagios-statd" >< ret) {

 vers = string("unknown");

 version = eregmatch(pattern:"^nagios-statd ([0-9.]+)$", string: ret);
 
 if(!isnull(version[1])) {
  vers = version[1];
 } 

 set_kb_item(name:"nagios_statd/"+port+"/Version", value:vers);
 register_service(port:port, ipproto:"tcp", proto:"nagios_statd");

 ## build cpe and store it as host_detail
 cpe = build_cpe(value: vers, exp:"^([0-9.]+)",base:"cpe:/a:nagios:nagios:");
 if(!isnull(cpe))
    register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

 tests = make_list("uptime","disk");
 
 foreach do (tests) {

   soc = open_sock_tcp(port); 
   req = string(do, "\r\n"); 
   send(socket:soc, data:req);

   result += string(do,":\n");

   while (data = recv_line(socket:soc, length:100)) {

    result += data;

   }

   result += string("\n");
   close(soc);
 }

 if(strlen(result)) {

   info = string("\n\nHere are a few Information from the nagios-statd daemon received by OpenVAS:\n\n");
   info += result;

   desc = desc + info; 

 }  

  if(report_verbosity > 0) { 
     security_note(port:port,data:desc);
   }  

  exit(0);

}

exit(0);
