##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_progea_movicon_tcpuploadserver_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Progea Movicon 'TCPUploadServer.exe' Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to perform unauthorised actions,
  obtain sensitive information and cause denial-of-service conditions.
  Impact Level: Application.";
tag_affected = "Progea Movicon version 11.2 Build prior to 1084";

tag_insight = "Multiple flaws are due to error in 'TCPUploadServer.exe', allows the
  attackers to data leakage, data manipulation or denial of service.";
tag_solution = "Upgrade to Progea Movicon 11.2 Build 1084 or later,
  For updates refer to http://www.progea.com/";
tag_summary = "This host is running Progea Movicon and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801969);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-2963");
  script_bugtraq_id(46907);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Progea Movicon 'TCPUploadServer.exe' Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/72888");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17034/");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-056-01.pdf");

  script_description(desc);
  script_summary("Check for the multiple vulnerabilities in Progea Movicon");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


## Check for the default port
port=10651;

## Check port status
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct the attack string
data= "MovX7" + raw_string(0x00);

## Send the attack string
send(socket:soc, data:data);
rcv = recv(socket:soc, length:1024);

## Check the response and confirm the exploit
if("MovX7" >< rcv && "Service Pack" >< rcv){
  security_hole(port);
}
