##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netoffice_dwins_mult_sql_injection_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# netOffice Dwins Multiple SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow the attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "netOffice Dwins version 1.4p3 and prior";

tag_insight = "Input passed via the 'S_ATSEL' parameter to reports/export_leaves.php and
  reports/export_person_performance.php and 'id' parameter to
  expenses/approveexpense.php, calendar/exportcalendar.php,
  analysis/expanddimension.php, and analysis/changedimensionsortingorder.php
  is not properly sanitized before being used in a SQL query.";
tag_solution = "No solution or patch is available as of 15th November, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/netofficedwins/";
tag_summary = "This host is running netOffice Dwins and is prone to multiple sql
  injection vulnerabilities.";

if(description)
{
  script_id(802493);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-15 16:26:54 +0530 (Thu, 15 Nov 2012)");
  script_name("netOffice Dwins Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/87104");
  script_xref(name : "URL" , value : "http://osvdb.org/87105");
  script_xref(name : "URL" , value : "http://osvdb.org/87107");
  script_xref(name : "URL" , value : "http://osvdb.org/87108");
  script_xref(name : "URL" , value : "http://osvdb.org/87109");
  script_xref(name : "URL" , value : "http://osvdb.org/87110");
  script_xref(name : "URL" , value : "http://osvdb.org/87111");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51198");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79962");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22590/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118010/netOffice-Dwins-1.4p3-SQL-Injection.html");

  script_description(desc);
  script_summary("Check if netOffice Dwins is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

port = "";

## Get HTTP port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/netoffice", "/Dwins", "", cgi_dirs()))
{
  url = dir + "/general/login.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, pattern:">netOffice Dwins",
     check_header:TRUE, extra_check:make_list('>Powered by netOffice Dwins',
     'Log In<')))
  {
    ## Construct the Attack Request
    url = dir + "/expenses/approveexpense.php?id=-1%20union%20select%200," +
          "SQL-Iniection-Test-&auth=-1&doc=-1";

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, pattern:"'SQL-Iniection-Test-",
       check_header:TRUE, extra_check:make_list("SQL syntax;","approveexpense.php")))
    {
      security_hole(port);
      exit(0);
    }
  }
}
