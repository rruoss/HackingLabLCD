###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_web_cookbook_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Web Cookbook Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site,
  compromise the application and inject or manipulate SQL queries in the
  back-end database,
  Impact Level: Application";

tag_affected = "Web Cookbook versions 0.9.9 and prior";
tag_insight = "Input passed via 'sstring', 'mode', 'title', 'prefix', 'postfix',
  'preparation', 'tipp', 'ingredient' parameters to searchrecipe.php,
  showtext.php, searchrecipe.php scripts is not properly sanitised before
  being returned to the user.";
tag_solution = "No solution or patch is available as of 14th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/webcookbook";
tag_summary = "This host is installed with Web Cookbook and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803437);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58441);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-14 13:10:16 +0530 (Thu, 14 Mar 2013)");
  script_name("Web Cookbook Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/91273");
  script_xref(name : "URL" , value : "http://osvdb.org/91273");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24742");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120760/");
  script_xref(name : "URL" , value : "http://security-geeks.blogspot.in/2013/03/web-cookbook-sql-injection-xss.html");

  script_description(desc);
  script_summary("Check if Web Cookbook is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/cookbook", "/webcookbook", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && "/projects/webcookbook/" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + "/searchrecipe.php?mode=1&title=<script>alert('XSS-Test')</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
             pattern:"<script>alert\('XSS-Test'\)</script>"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
