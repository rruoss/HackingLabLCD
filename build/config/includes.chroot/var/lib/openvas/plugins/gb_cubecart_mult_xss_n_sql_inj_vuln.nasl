##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cubecart_mult_xss_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CubeCart Multiple Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "CubeCart version 4.3.3";
tag_insight = "The flaws are due to
  - Input passed to the 'amount', 'cartId', 'email', 'transId', and
    'transStatus' parameters in 'modules/gateway/WorldPay/return.php' is not
    properly sanitised before being returned to the user.
  - Input passed via the 'searchStr' parameter to index.php
    (when '_a' is set to 'viewCat') is not properly sanitised before being used
    in a SQL query.";
tag_solution = "Upgrade to CubeCart version 4.4.2 or later
  For updates refer to http://www.cubecart.com/tour";
tag_summary = "This host is running CubeCart and is prone to SQL injection and
  multiple cross-site scripting vulnerabilities.";

if(description)
{
  script_id(802199);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-4903");
  script_bugtraq_id(43114);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-04 11:10:29 +0200 (Fri, 04 Nov 2011)");
  script_name("CubeCart Multiple Cross-Site Scripting and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41352");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513572/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.acunetix.com/blog/web-security-zone/articles/sql-injection-xss-cubecart-4-3-3/");

  script_description(desc);
  script_summary("Check if CubeCart is vulnerable for SQL injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

foreach dir (make_list("/cart", "/store", "/shop", "/cubecart", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: string(dir, "/admin.php?_g=login&goto=%2Fcubecart%2F" +
                        "admin.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the Application
  if("<title>CubeCart" >< res)
  {
    ## Try attack and check the response to confirm vulnerability
    url = string(dir, "/index.php?searchStr='&_a=viewCat&Submit=Go");

    if(http_vuln_check(port:port, url:url, pattern:"You have an error " +
              "in your SQL syntax;", extra_check:"> SELECT id FROM cube_" +
              "CubeCart_search WHERE searchstr="))
    {
      security_hole(port);
      exit(0);
    }
  }
}
