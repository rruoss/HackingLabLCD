###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_santafox_xss_n_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Santafox Cross-Site Scripting and Cross-Site Request Forgery Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "SantaFox 2.02 and prior.";
tag_insight = "The flaws are caused by,
  - improper validation of user-supplied input passed via the 'search' parameter
  to search.html, that allows attackers to execute arbitrary HTML and script
  code on the web server.
  - Cross-site request forgery vulnerability in admin/manager_users.class.php,
  allows remote attackers to hijack the authentication of administrators.";
tag_solution = "No solution or patch is available as of 27th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.santafox.ru/download.html";
tag_summary = "The host is running Santafox and is prone to Cross-Site
  Scripting and Cross-Site Request Forgery vulnerabilities.";

if(description)
{
  script_id(901158);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3463","CVE-2010-3464");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Santafox Cross-Site Scripting and Cross-Site Request Forgery Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41465");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/santafox-xssxsrf.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513737/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513738/100/0/threaded");

  script_description(desc);
  script_summary("Check if Santafox is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
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

foreach dir (make_list("/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if("Santafox" >< res)
  {
    ## Construct the Attack Request
    url = dir+ 'search.html?search=1"><script>alert(document.cookie)</script>&x=0&y=0';

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, pattern:"<script>alert" +
                                           "\(document.cookie\)</script>"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
