###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmydirectory_id_param_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# phpMyDirectory 'id' Parameter SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will let attacker to inject or manipulate SQL queries
  in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data.
  Impact Level: Application";
tag_affected = "phpMyDirectory version 1.3.3";
tag_insight = "Input passed via the 'id' parameter to page.php is not properly sanitised
  before being used in SQL queries.";
tag_solution = "Upgrade to phpMyDirectory version 1.4.1 or later,
  For updates refer to http://www.phpmydirectory.com/";
tag_summary = "The host is running phpMyDirectory and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(802977);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5288");
  script_bugtraq_id(51342);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-05 16:54:35 +0530 (Fri, 05 Oct 2012)");
  script_name("phpMyDirectory 'id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/78335");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47471");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72232");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18338/");

  script_description(desc);
  script_summary("Determine if phpMyDirectory is prone to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
port = "";
dir = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Port state
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port)){
  exit(0);
}

foreach dir (make_list("", "/phpMyDirectory", "phpmydirectory", "/pmd", cgi_dirs()))
{
  ## Create req
  url = dir + '/index.php';

  ## Confirmation application
  if(http_vuln_check(port:port, url:url, pattern:'>phpMyDirectory.com<',
                                         check_header: TRUE))
  {
    ## Constuct attack request
    url = dir + "/page.php?id='";

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url,check_header: TRUE,
                       pattern:'You have an error in your SQL syntax;'))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
