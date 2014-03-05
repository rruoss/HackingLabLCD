##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easyphp_web_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# EasyPHP Webserver Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to gain administrative access,
  disclose the information, inject PHP code/shell and execute a remote PHP
  Code.
  Impact Level: Application";
tag_affected = "EasyPHP version 12.1 and prior";


tag_insight = "The bug in EasyPHP WebServer Manager, its skipping authentication for
  certain requests. Which allows to bypass the authentication, disclose
  the information or execute a remote PHP code.";
tag_solution = "No solution or patch is available as of 09th, April 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.easyphp.org/";
tag_summary = "This host is running EasyPHP Webserver and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803189);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-09 11:29:34 +0530 (Tue, 09 Apr 2013)");
  script_name("EasyPHP Webserver Multiple Vulnerabilities");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/easyphp-webserver-php-command-execution");
  script_summary("Try to read the content of 'phpinfo.php' file");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

## Variable Initialization
port = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

if (!can_host_php(port:port)){
  exit(0);
}

#[EasyPHP] - Administration<
if(http_vuln_check(port:port, url:"/phpinfo.php",
   pattern:"\[EasyPHP\]", check_header:TRUE,
   extra_check:make_list(">Configuration<", ">PHP Core<", "php.ini")))
{
  security_hole(port:port);
  exit(0);
}
