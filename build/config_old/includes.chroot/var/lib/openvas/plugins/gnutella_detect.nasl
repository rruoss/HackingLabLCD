# OpenVAS Vulnerability Test
# $Id: gnutella_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Gnutella servent detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "We detected a Gnutella 'servent'.
This file sharing software works in peer to peer mode.";

desc = "
 Summary:
 " + tag_summary;



if(description)
{
 script_id(10946);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");

 name = "Gnutella servent detection";
 script_name(name);

 
 script_description(desc);

 summary = "Detect Gnutella servent";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Peer-To-Peer File Sharing";
 script_family(family);

 script_dependencies("find_service.nasl");
 # Gnutella servent _might_ be detected as a web server
 script_require_ports("Services/www", 6346);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("http_func.inc");

function check(port)
{
 if (! get_port_state(port))
  return (0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:string("GNUTELLA CONNECT/0.4\r\n\r\n"));
  answer = recv(socket:soc, length:500);
  close(soc);
  # display(string(">", answer, "<\n"));

  if ("GNUTELLA OK" >< answer)
  {
   security_note(port:port, protocol:"tcp");
   register_service(port:port, proto:"gnutella");
   return(1);
  }
 }
 else exit(0);

 banner = get_kb_item(string("www/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    send(socket:soc, data:string("GET / HTTP/1.0\r\n\r\n"));
    banner = http_recv(socket:soc);
    close(soc);
   }
   else exit(0);
  }
 }
 
 
 if (! banner)
  return(0);

 # We should probably add more regex here. But there are 100+ Gnutella
 # softwares
 if (egrep(pattern:"Gnutella|BearShare", string:banner, icase:1))
 {
report = "Although this service did not answer to Gnutella protocol 0.4,
it might be a Gnutella server.";

  security_note(port:port, protocol:"tcp",data:report);
  return(1);
 }
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:6346);
foreach port (ports)
{
check(port:defp);
}
