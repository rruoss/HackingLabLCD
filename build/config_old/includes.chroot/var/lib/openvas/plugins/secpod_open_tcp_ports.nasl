###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_open_tcp_ports.nasl 44 2013-11-04 19:58:48Z jan $
#
# Checks for open tcp ports
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "Collects all open tcp ports of the
tcp ports identified so far.";

if(description)
{
  script_id(900239);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Checks for open tcp ports");
  script_description("
  Summary:
  " + tag_summary);
  script_summary("Check Open TCP Ports");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# Note: secpod_ssl_ciphers* and ssl_cert_details are the only NVTs
# using "TCP/PORTS" created here. It might make sense to consolidate
# this with host_details mechanism.

include("host_details.inc");

opened_tcp_ports = "";

## Get all tcp ports
tcp_ports = get_kb_list("Ports/tcp/*");
if(!tcp_ports) {
  log_message(data:"Open TCP ports: [None found]");
  exit(0);
}

foreach port (keys(tcp_ports))
{
  ## Extract port number
  Port = eregmatch(string:port, pattern: "Ports/tcp/([0-9]+)");
  if(!Port && !get_port_state(Port[1])){
    continue;
  }
  set_kb_item(name:"TCP/PORTS", value: Port[1]);
  opened_tcp_ports += Port[1] + ", ";
}

if(strlen(opened_tcp_ports)) {
  opened_tcp_ports = ereg_replace(string:chomp(opened_tcp_ports),pattern:",$", replace:"");
  opened_tcp_ports_kb = str_replace(string: opened_tcp_ports,find:" ",replace:"");
  set_kb_item(name:"Ports/open/tcp", value:opened_tcp_ports_kb);
  register_host_detail(name:"ports", value:opened_tcp_ports_kb,
    nvt:"1.3.6.1.4.1.25623.1.0.900239", desc:"Check Open TCP Ports");
  register_host_detail(name:"tcp_ports", value:opened_tcp_ports_kb,
    nvt:"1.3.6.1.4.1.25623.1.0.900239", desc:"Check Open TCP Ports");

  log_message(data:"Open TCP ports: "+ opened_tcp_ports);
} else {
  log_message(data:"Open TCP ports: [None found]");
}
