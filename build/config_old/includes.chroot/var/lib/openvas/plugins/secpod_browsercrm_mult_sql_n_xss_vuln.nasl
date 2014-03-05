##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_browsercrm_mult_sql_n_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# BrowserCRM Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "BrowserCRM version 5.100.1 and prior";

tag_insight = "Multiple flaws are due to inputs passed via
  - The 'PATH_INFO' to index.php, modules/admin/admin_module_index.php, or
    modules/calendar/customise_calendar_times.php, 'login[]' parameter to
    index.php or pub/clients.php and 'framed' parameter to licence/index.php
    or licence/view.php is not properly verified before it is returned to
    the user.
  - The 'login[username]' parameter to index.php, 'parent_id' parameter to
    modules/Documents/version_list.php or 'contact_id' parameter to
    modules/Documents/index.php is not properly sanitized before being used
    in a SQL query.";
tag_solution = "No solution or patch is available as of 30th October, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.browsercrm.com/content/view/139/125/";
tag_summary = "This host is running BrowserCRM and is prone to multiple sql
  injection and cross site scripting vulnerabilities.";

if(description)
{
  script_id(902691);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5213", "CVE-2011-5214");
  script_bugtraq_id(51060);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-30 12:15:54 +0530 (Tue, 30 Oct 2012)");
  script_name("BrowserCRM Multiple SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/77728");
  script_xref(name : "URL" , value : "http://www.osvdb.org/77735");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47217");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71828");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23059");

  script_description(desc);
  script_summary("Check if BrowserCRM is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP port
bcrmPort = get_http_port(default:80);
if(!get_port_state(bcrmPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:bcrmPort)){
  exit(0);
}

foreach dir (make_list("/browserCRM", "/browsercrm", "/browser", "", cgi_dirs()))
{
  url = dir + "/index.php";

  if(http_vuln_check(port:bcrmPort, url:url, pattern:">BrowserCRM<",
                 check_header:TRUE, extra_check:'please log in'))
  {
    ## Construct the Attack Request
    url = url + '/"><script>alert(document.cookie);</script>';

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:bcrmPort, url:url,
                       pattern:"><script>alert\(document.cookie\);</script>",
                       check_header:TRUE,
                       extra_check:">BrowserCRM<"))
    {
      security_hole(bcrmPort);
      exit(0);
    }
  }
}
