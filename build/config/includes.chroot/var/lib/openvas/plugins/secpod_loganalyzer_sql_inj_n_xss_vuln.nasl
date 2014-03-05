##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_loganalyzer_sql_inj_n_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or  exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "Adiscon LogAnalyzer version 3.4.2 and prior";
tag_insight = "Multiple flaws are due to
  - Input passed via the 'filter' parameter to index.php, the 'id' parameter to
    admin/reports.php and admin/searches.php is not properly sanitised before
    being returned to the user.
  - Input passed via the 'Columns[]' parameter to admin/views.php is not
    properly sanitised before being used in SQL queries.";
tag_solution = "Upgrade to Adiscon LogAnalyzer version 3.4.3 or later,
  For updates refer to http://loganalyzer.adiscon.com/";
tag_summary = "This host is running Adiscon LogAnalyzer and is prone to multiple
  SQL injection and cross site scripting vulnerabilities.";

if(description)
{
  script_id(902840);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53664);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-28 15:15:15 +0530 (Mon, 28 May 2012)");
  script_name("Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/82137");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49223");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113037/CSA-12005.txt");
  script_xref(name : "URL" , value : "http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer");
  script_xref(name : "URL" , value : "http://loganalyzer.adiscon.com/news/loganalyzer-v3-4-3-v3-stable-released");

  script_description(desc);
  script_summary("Check if LogAnalyzer is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
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
    url += "?filter=</title><script>alert(document.cookie)</script>";

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check( port: port, url: url, check_header: TRUE,
                        pattern: "<script>alert\(document.cookie\)</script>",
                        extra_check: ">Adiscon LogAnalyzer<"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
