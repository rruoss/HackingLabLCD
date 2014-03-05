###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rpc_rstatd.nasl 13 2013-10-27 12:16:33Z jan $
#
# Check RPC rstatd Service Running
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "rstatd service an rpc server which provides remotely monitorable statistics
  obtained from the kernel such as,
  - system uptime
  - cpu usage
  - disk usage
  - network usage
  - load averages
  - and more

  Impact Level: System";

tag_solution = "Disable rstatd service, If not needed.";
tag_summary = "This remote host is running rstatd service.";

if(description)
{
  script_id(901206);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-1999-0624");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Check RPC rstatd Service Running");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/115");
  script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Remote_procedure_call");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/advice/Services/SunRPC/rpc.rstatd/default.htm");

  script_description(desc);
  script_summary("Check for RPC rstatd Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("find_service.nasl");
  script_family("Useless services");
  script_dependencies("secpod_rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}

##
## The script code starts here
##

include("misc_func.inc");
include("byte_func.inc");

## RPC rstatd Program ID
RPC_PROG = 100001;

## Default protocol is UDP
proto = "udp";

## Get rstatd udp port, if not tcp port
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
  port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
  proto = "tcp";
}

## Exit if it's not listening
if(!port){
  exit(0);
}

## Open UDP socket if it's UDP, else open TCP socket
if(proto == "udp"){
  soc = open_sock_udp(port);
}else{
  soc = open_sock_tcp(port);
}

data = NULL;
## Construct RPC Packet
rpc_paket = construct_rpc_packet(program:RPC_PROG, prog_ver:3,
                           procedure:1, data:data, udp:proto);

## Send and Receive response
send(socket:soc, data:rpc_paket);
resp = recv(socket:soc, length:4096);

## Close Scoket
close(soc);

## It's not a proper response, If response length < 100 and > 130
if(strlen(resp) < 100 || strlen(resp) > 150){
  exit(0);
}

## Accept state position
pos = 20;

## If protocol is TCP then replay will
## be having 4 bytes of Fragment header
if(proto == "tcp"){
  pos = 20 + 4;
}

## Confirm rstat response by
## Checking Accept State: RPC executed successfully (0)
if(ord(resp[pos]) == 0 && ord(resp[pos+1]) == 0 &&
   ord(resp[pos+2]) == 0 && ord(resp[pos+3]) == 0){
  log_message(port);
  exit(0);
}
