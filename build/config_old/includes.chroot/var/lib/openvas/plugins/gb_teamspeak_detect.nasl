###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamspeak_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Teamspeak Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "This host is running Teamspeak. TeamSpeak is proprietary Voice over IP
software that allows users to speak on a chat channel with other
users, much like a telephone conference call.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100681);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Teamspeak Detection");
 script_description(desc);
 script_summary("Checks for the presence of Teamspeak");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(10011);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.teamspeak.com/");
 exit(0);
}

port = 10011;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = recv(socket:soc, length:16);
if( buf == NULL )exit(0);
if("TS" >!< buf)exit(0);

send(socket:soc, data:string("version\n"));
buf = recv(socket:soc, length:256);

if("version" >!< buf && "msg" >!< buf)exit(0);

version = eregmatch(pattern:"version=([^ ]+) (build=([^ ]+))*", string:buf);
if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(version[3]))vers = vers + ' build=' + version[3];

set_kb_item(name: string("teamspeak/",port), value: vers);

info = string("com/\n\nTeamspeak ");
info += string(vers);
info += string("' was detected on the remote host\n"); 

desc = ereg_replace(
  string:desc,
  pattern:"com/$",
  replace:info
);

security_note(port:port,data:desc);
exit(0);	       
