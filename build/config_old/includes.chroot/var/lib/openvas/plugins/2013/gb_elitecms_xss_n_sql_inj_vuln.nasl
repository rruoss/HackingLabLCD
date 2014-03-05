###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elitecms_xss_n_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Elite Graphix ElitCMS Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804029";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-21 19:27:04 +0530 (Mon, 21 Oct 2013)");
  script_name("Elite Graphix ElitCMS Cross Site Scripting and SQL Injection Vulnerabilities");

  tag_summary =
"This host is running Elite Graphix ElitCMS and is prone to xss and sql
injection vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to execute sql query
or not.";

  tag_insight =
"Multiple flaws are due to improper sanitation of user-supplied input passed
via 'page' and 'subpage' parameters to index.php script.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code, inject or manipulate SQL queries in the back-end database
allowing for the manipulation or disclosure of arbitrary data.

Impact Level: Application";

  tag_affected =
"Elite Graphix ElitCMS version 1.01, Other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 21st October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://elitecms.net";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123672");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=1117");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/elite-graphix-elitcms-101-pro-cross-site-scripting-sql-injection");
  script_summary("Check if Elite Graphix ElitCMS is prone to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/elite", "/cms", "/elitecms", cgi_dirs()))
{
  ## Confirm the application before trying exploit
  if(http_vuln_check(port:http_port, url: dir + "/admin/login.php",
                     check_header: TRUE, pattern:">EliteCMS"))
  {
    ## Malformed URL
    url = dir + "/index.php?page=-1'SQL-Injection-Test";

    if(http_vuln_check(port:http_port, url: url, check_header: TRUE,
                       pattern:"Database Query failed !.*SQL-Injection-Test"))
    {
      security_hole(http_port);
      exit(0);
    }
  }
}
