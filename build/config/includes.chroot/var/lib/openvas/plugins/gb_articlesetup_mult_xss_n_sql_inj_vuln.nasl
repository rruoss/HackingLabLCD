###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_articlesetup_mult_xss_n_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# ArticleSetup Multiple Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "ArticleSetup version 1.11 and prior";
tag_insight = "Multiple flaws are due to an,
  - Input passed to 'userid' and 'password' parameter in '/upload/login.php'
    and '/upload/admin/login.php' page is not properly verified before being
    used.
  - Input passed to the 'cat' parameter in 'upload/feed.php', 's' parameter in
    'upload/search.php', 'id' parameter in '/upload/admin/pageedit.php',
    'upload/admin/authoredit.php' and '/admin/categoryedit.php' pages are  not
    properly verified before being used.
  - Input passed to the 'title' parameter in 'upload//author/submit.php',
    '/upload/admin/articlenew.php', '/upload/admin/categories.php' and
    '/upload/admin/pages.php' pages are not properly verified before being
    used.";
tag_solution = "No solution or patch is available as of 04th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.articlesetup.com/";
tag_summary = "This host is running ArticleSetup and is prone to multiple cross-site
  scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(802427);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52834);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-04 11:17:27 +0530 (Wed, 04 Apr 2012)");
  script_name("ArticleSetup Multiple Cross-Site Scripting and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=497");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18682/");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_ArticleSetup_Multiple_Vuln.txt");

  script_description(desc);
  script_summary("Check if ArticleSetup is vulnerable to XSS and SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
dir = "";
exploit = "";
exploits = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/ArticleSetup", cgi_dirs()))
{
  if(http_vuln_check(port:port, url: dir + "/upload/index.php", pattern:">Art" +
     "icle Script</", extra_check: make_list(">Most Viewed","All Categories<",
     ">Submit Articles<")))
  {
    exploits = make_list("/upload/search.php?s='",
                         "/upload/search.php?s=<script>alert(document.cookie)</script>");

    ## Iterate over each exploit
    foreach exploit(exploits)
    {
      ## Try attack and check the response to confirm vulnerability.
      if(http_vuln_check(port:port, url: dir + exploit,
         pattern:"You have an error in your SQL syntax;|<script>alert\(docum" +
         "ent.cookie\)</script>", extra_check:make_list(">Submit Articles<", "All" +
         " Categories<")))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
