###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lost_door_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Lost Door J-Revolution Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will let remote unauthenticated attackers to
  cause a denial of service condition.
  Impact Level: Application";
tag_affected = "Lost Door J-Revolution version 6";
tag_insight = "The flaw is due to error in handling the message used by LastDoor
  which uses a simple clear text protocol with a delimitter.";
tag_solution = "No solution or patch is available as of 1st June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://donofjsr.blogspot.com/2011/03/lostdoor-j-revolution-v6.html";
tag_summary = "This host is running Lost Door J-Revolution and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(801943);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Lost Door J-Revolution Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16203");
  script_xref(name : "URL" , value : "http://donofjsr.blogspot.com/2011/03/lostdoor-j-revolution-v6.html");

  script_description(desc);
  script_summary("Check Lost Door J-Revolution is vulnerable by sending crafted pacakets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(7183);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Default Lost Door J-Revolution Port 7183
ldPort = 7183 ;

## exit if ports are not listening
if(!get_port_state(ldPort)){
  exit(0);
}

## Open TCP Socket and immediately close the socket
## without sending any data this will trigger an exception
## at server side causing denial of service
soc = open_sock_tcp(ldPort);
if(!soc){
  exit(0);
}
close(soc);

sleep(5);

## Check still Lost Door J-Revolution is listening
soc = open_sock_tcp(ldPort);
if(!soc){
  security_warning(ldPort);
}

close(soc);
