##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kb_publisher_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# KBPublisher Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "KBPublisher version 4.0";
tag_insight = "- Input passed via the 'Type' parameter to 'browser.html' is not properly
    sanitised before being returned to the user.
  - Input passed via the 'id' parameter to 'admin/index.php' is not properly
    sanitised before being used in SQL queries.
  - Input passed via the 'sid' parameter to 'index.php' is not properly
    sanitised before being used .";
tag_solution = "No solution or patch is available as of 11th, June 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to  http://www.kbpublisher.com/";
tag_summary = "This host is running KBPublisher and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802434);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-11 14:44:53 +0530 (Mon, 11 Jun 2012)");
  script_name("KBPublisher Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18467");
  script_xref(name : "URL" , value : "http://mondoristoranti.com/kbpublisher-v4-0-multiple-vulnerabilties/");
  script_xref(name : "URL" , value : "http://www.allinfosec.com/2012/06/07/webapps-0day-kbpublisher-v4-0-multiple-vulnerabilties/");

  script_description(desc);
  script_summary("Check if KBPublisher vulnerable to cross site scripting");
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


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
dir = "";
url = "";

## Get HTTP port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/kb", "/kbp",  cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: ">KBPublisher<",  extra_check: "Knowledge base software"))
  {
    ## Construct attack request
    url = dir + '/?&sid="><script>alert(document.cookie)</script>';

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check( port: port, url: url, check_header: TRUE,
       pattern:"><script>alert\(document.cookie\)</script>" ,
       extra_check: ">KBPublisher<"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
