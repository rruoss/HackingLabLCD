###############################################################################
# OpenVAS Vulnerability Test
# $Id: auth_enabled.nasl 43 2013-11-04 19:51:40Z jan $
#
# Check for ident Service 
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
tag_summary = "The remote host is running an ident daemon.

   The Ident Protocol is designed to work as a server daemon, on a user's
   computer, where it receives requests to a specified port, generally 113. The
   server will then send a specially designed response that identifies the
   username of the current user.

   The ident protocol is considered dangerous because it allows hackers to gain
   a list of usernames on a computer system which can later be used for attacks.";


if(description)
{
 script_id(100081);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Check for ident Service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 summary = "Check for ident Service";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/auth", 113);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/auth");
if(!port)port = 113;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
 
  data = strcat(port, ',', get_source_port(soc));
  send(socket:soc, data:string(data,"\r\n"));
  buf = recv_line(socket:soc, length:1024);

  if("ERROR" >< buf || data >< buf || "USERID" >< buf)
  {
   security_note(port);
   register_service(port:port, proto:"auth");
  }
  close(soc);

exit(0);  
