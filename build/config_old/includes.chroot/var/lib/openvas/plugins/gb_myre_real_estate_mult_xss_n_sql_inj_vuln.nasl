###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_myre_real_estate_mult_xss_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MYRE Real Estate Software Multiple XSS and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attack to gain sensitive information.
  Impact Level: Application";
tag_affected = "MYRE Real Estate Software.";
tag_insight = "The flaws are due to input passed to the
  - 'page' parameter in findagent.php is not properly sanitized before being
    used in SQL queries.
  - 'country1', 'state1', and 'city1' parameters in findagent.php are not
    properly verified before it is returned to the user.";
tag_solution = "No solution or patch is available as of 9th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://myrephp.com/";
tag_summary = "The host is running MYRE Real Estate Software and is prone to
  multiple cross site scripting and SQL injection vulnerabilities";

if(description)
{
  script_id(802157);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_bugtraq_id(49540);
  script_cve_id("CVE-2011-3393", "CVE-2011-3394");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("MYRE Real Estate Software Multiple XSS and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=346");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17811");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_MRS_SQL_XSS_Vuln.txt");

  script_description(desc);
  script_summary("Check if MYRE Real Estate Software is prone to XSS and SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list("/realestate", "", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: string (dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('MYRE Real Estate Software' >< res)
  {
    ## Try XSS exploit
    req = http_get(item:string(dir, "/findagent.php?country1=<script>alert" +
                          "(/document.cookie/)</script>"), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    # check the response to confirm vulnerability
    if('"><script>alert(/document.cookie/)</script>' >< res){
      security_hole(port:port);
      exit(0);
    }

    ## Check for the SQL injection
    req = http_get(item:string(dir, "/findagent.php?page='"), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Check the SQL result
    if(">You have an error in your SQL syntax;" >< res)
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
