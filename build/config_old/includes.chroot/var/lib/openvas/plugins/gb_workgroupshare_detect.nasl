###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_workgroupshare_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# WorkgroupShare Detection
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
tag_summary = "This host is running a WorkgroupShare Server. WorkgroupShare lets the
people share their personal Outlook folders, such as calendar,
contact, task and notes information by using standard internet
protocols.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;
if (description)
{
 script_id(100518);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-05 14:01:46 +0100 (Fri, 05 Mar 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("WorkgroupShare Detection");
 script_description(desc);
 script_summary("Checks for the presence of WorkgroupShare");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","find_service1.nasl");
 script_require_ports("Services/WorkgroupShare", 8100);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = get_kb_item("Services/WorkgroupShare");
if(!port)port = 8100;

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);

if(!soc)exit(0);
send(socket:soc, data:"\n");
buf = recv(socket:soc, length:512);
if( buf == NULL )exit(0);

if("OK WorkgroupShare" >< buf) {

  version = eregmatch(pattern: "WorkgroupShare ([0-9.]+)", string:buf);

  if(!isnull(version[1])) {
    ver = version[1];
    info = string("\n\nWorkgroupShare version '", ver,"' was found on the remote Host.\n");
    desc = desc + info;	
  }  

  security_note(port:port, data:desc);
  exit(0);
}  

exit(0);




