###############################################################################
# OpenVAS Vulnerability Test
# $Id: xmpp_detect.nasl 50 2013-11-07 18:27:30Z jan $
#
# XMPP Detection
#
# Authors:
# Michael Meyer
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
tag_summary = "This host is running the Extensible Messaging and Presence Protocol (XMPP)
(formerly named Jabber). XMPP is an open, XML-based protocol originally aimed at
near-real-time, extensible instant messaging (IM) and presence information
(e.g., buddy lists), but now expanded into the broader realm of
message-oriented middleware.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100489);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 50 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("XMPP Detection");

 script_description(desc);
 script_summary("Checks for the presence of XMPP Protocol");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 5222);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Jabber");
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

function delete_user(soc) {

  req = string("<iq id='A4' type='set'>
                 <query xmlns='jabber:iq:register'>
                  <remove/>
                 </query>
                </iq> ");

  send(socket:soc, data:req);
  buf = recv(socket:soc,length:512);
  close(soc);
  
  return 0;
}  

port = 5222;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

get_from = string("<stream:stream
		   to='",get_host_name,"'
		   xmlns='jabber:client'
		   xmlns:stream='http://etherx.jabber.org/streams'>");

send(socket:soc, data:get_from);
buf = recv(socket:soc, length:512);
if(isnull(buf) || "xmlns:stream=" >!< buf || "jabber:client" >!< buf) { 
  close(soc);
  exit(0);
}  

register_service(port: port, ipproto:"tcp", proto: 'xmpp');

close(soc);

FROM = eregmatch(pattern:"from='([^']+)'", string:buf);
if(isnull(FROM[1]))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("<stream:stream
	      to='",FROM[1],"'
	      xmlns='jabber:client'
	      xmlns:stream='http://etherx.jabber.org/streams'>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);

if(isnull(buf) || "<?xml" >!< buf || "host-unknown" >< buf) {
  close(soc);
  exit(0);
}

req = string("<iq id='A0' type='get'>
	       <query xmlns='jabber:iq:register'/>
	      </iq>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);
if(isnull(buf) || "instructions" >!< buf) {
  close(soc);
  exit(0);
}  

USER = string("OpenVAS",rand());

req = string("<iq id='A1' type='set'>
	       <query xmlns='jabber:iq:register'>
	        <username>",USER,"</username>
	        <password>",USER,"</password>
	        <name>",USER,"</name>
	        <email>openvas@openvas.org</email>
	       </query>
	      </iq>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);
if(isnull(buf) || USER >!< buf) {
  close(soc);
  exit(0);
}  

req = string("<iq id='A2' type='get'>
	       <query xmlns='jabber:iq:auth'>
	        <username>",USER,"</username>
	       </query>
	      </iq>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);
if(isnull(buf) || USER >!< buf) {
  delete_user(soc: soc);
  exit(0);
}  

req = string("<iq id='A3' type='set'>
 	       <query xmlns='jabber:iq:auth'>
	        <username>",USER,"</username>
		<resource>telnet</resource>
	        <password>",USER,"</password>
	       </query>
	      </iq>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);
if("result" >!< buf) {
  delete_user(soc: soc);
  exit(0);
}

req = string("<iq to='",FROM[1],"' type='get'>
	       <query xmlns='jabber:iq:version'>
	       </query>
	      </iq>");

send(socket:soc, data:req);
buf = recv(socket:soc,length:512);

if("<version>" >!< buf || "<name>" >!< buf) {
  delete_user(soc: soc);
  exit(0);
}  

version = eregmatch(pattern: "<version>(.*)</version>", string: buf);
server = eregmatch(pattern: "<name>(.*)</name>", string: buf);

if(!isnull(server[1])) {
  server_name = server[1];
  set_kb_item(name: string("xmpp/",port,"/server"), value: server_name);
}  

if(!isnull(version[1])) {
  server_version = version[1];
  set_kb_item(name: string("xmpp/",port,"/version"), value: server_version);
}

delete_user(soc: soc);

if(server_name && server_version) {
 
  info = string("\n\nXMPP Server '",server_name, "' version '", server_version, "' was detected by OpenVAS.\n");
  desc = desc + info;
 
}

if(report_verbosity > 0) {
  security_note(port:port,data:desc);
  exit(0);
}

exit(0);
