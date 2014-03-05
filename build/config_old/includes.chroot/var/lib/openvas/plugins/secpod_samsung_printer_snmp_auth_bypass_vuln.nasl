###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_samsung_printer_snmp_auth_bypass_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Samsung Printer SNMP Hardcoded Community String Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_affected = "Samsung Printers firmware version prior to 20121031

  NOTE: Samsung has stated that models released after October 31, 2012 are not
        affected by this vulnerability. Samsung has also indicated that they
        will be releasing a patch tool later this year to address vulnerable
        devices.";

tag_impact = "Successful exploitation will allow attackers to access an affected device
  with administrative privileges, make changes to the device configuration and
  access to sensitive information.
  Impact Level: System/Application";
tag_insight = "Samsung printers (as well as some Dell printers manufactured by Samsung)
  contain a hardcoded SNMP full read-write community string that remains
  active even when SNMP is disabled in the printer management utility.";
tag_solution = "Upgrade Samsung Printer to 20121031 or later,
  http://www.samsung.com/in/consumer/pc-peripherals-printer/laser-printer-multifunction/";
tag_summary = "This host has Samsung Printer firmware and is prone to authentication bypass
  vulnerability.";

if(description)
{
  script_id(902935);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4964");
  script_bugtraq_id(56692);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-28 13:37:22 +0530 (Wed, 28 Nov 2012)");
  script_name("Samsung Printer SNMP Hardcoded Community String Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/281284");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/196");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118413/samsung-backdoor.txt");

  script_description(desc);
  script_summary("Check for authontication bypass vulnerability in Samsung Printers");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("SNMP");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("snmp_default_communities.nasl");
  script_require_udp_ports("Services/snmp", 161);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);


}

include("dump.inc");

p = get_kb_item("Services/snmp");
if(!p)p = 161;

ports = make_list(p,1118);

function parse_result(data) {

  if(strlen(data) < 8) return FALSE;

  for(v=0; v < strlen(data); v++) {

      if(ord(data[v]) == 43 && ord(data[v-1]) == 8) {
        ok = TRUE;
        break;
      }
      oid_len = ord(data[v]);
  }

  if(!ok || oid_len < 8)return FALSE;

  tmp = substr(data,(v+oid_len+2));

  if (!isprint (c:tmp[0])) {
    tmp = substr(tmp,1,strlen(tmp)-1);
  }

  return tmp;

}

function test(community,port) {

  local_var port, community;

  soc = open_sock_udp(port);
  if(!soc)return FALSE;

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen(community);

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;

  for (i=0; i<3; i++) {

    sendata = raw_string(
                  0x30, 0x82, len_hi, len_lo, 
                  0x02, 0x01, i, 0x04,
                  sz);


    sendata = sendata + community +
              raw_string(0xA1,0x18, 0x02,
                  0x01, 0x01, 0x02, 0x01,
                  0x00, 0x02, 0x01, 0x00,
                  0x30, 0x0D, 0x30, 0x82,
                  0x00, 0x09, 0x06, 0x05,
                  0x2B, 0x06, 0x01, 0x02,
                  0x01, 0x05, 0x00);

    send(socket:soc, data:sendata);
    result = recv(socket:soc, length:65535, timeout:1);
    close(soc);

    if(!result || ord(result[0]) != 48)return FALSE;

    if(res = parse_result(data:result)) {
      return res;
    }

  }

  return FALSE;

}

foreach port (ports) {

  if(!(get_udp_port_state(port)))continue;

  res = test(community:'lkjfhlsk',port:port); # make sure remote snmp doesn't accept any community.
  if(res)exit(0);;

  res = test(community:'s!a@m#n$p%c',port:port);
  if(!res)continue;

  res = tolower(res);

  if("samsung" >< res || "dell" >< res) {
    security_hole(port:port,proto:"udp");
    exit(0);
  }
}

exit(0);
