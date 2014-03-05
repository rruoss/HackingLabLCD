###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_surgemail_surgeweb_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SurgeMail SurgeWeb Cross Site Scripting Vulnerability
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
tag_affected = "NetWin Surgemail versions before 4.3g";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'username_ex' parameter to the SurgeWeb interface '/surgeweb', which allows
  the attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.";
tag_solution = "Upgrade to NetWin Surgemail version 4.3g or later.
  For updates refer to http://netwinsite.com/surgemail/";
tag_summary = "The host is running SurgeMail and is prone to Cross site scripting
  vulnerability.";

if(description)
{
  script_id(801808);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_cve_id("CVE-2010-3201");
  script_bugtraq_id(43679);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SurgeMail SurgeWeb Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://ictsec.se/?p=108");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41685");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514115/100/0/threaded");

  script_description(desc);
  script_summary("Determine if Surgemail is prone to XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Banner
banner = get_http_banner(port:port);

## Confirm the application
if(!banner && "surgemail" >< banner)
{
  ## Construct The Attack Request
  url = '/surgeweb?username_ex="/><script>alert(\'OpenVAS-XSS-Test\')</script>';

  ## Try attack and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('OpenVAS-" +
                     "XSS-Test'\)</script>", check_header: TRUE)){
    security_warning(port);
  }
}
