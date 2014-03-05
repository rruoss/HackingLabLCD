###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solgens_ecommerce_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# SolGens E-Commerce 'cid' And 'pid' Parameters SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to perform SQL injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "SolGens E-Commerce";
tag_insight = "The flaws are caused by improper validation of user-supplied input sent via
  the 'cid' and 'pid' parameters to 'product_detail.php',
  'category_products.php' and 'order_product.php' scripts, which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 02nd February, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.solgens.com/";
tag_summary = "This host is running SolGens E-Commerce and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(802387);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-01 13:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("SolGens E-Commerce 'cid' And 'pid' Parameters SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108947/solgensecommerce-sql.txt");

  script_description(desc);
  script_summary("Check if SolGens E-Commerce is vulnerable to SQL Injection Vulnerability");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/solgens", "/SolGens", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(egrep(pattern:">.?SolGens", string:rcvRes))
  {
    ## Construct the Attack Request
    url = dir + "/product_detail.php?pid='";

    if(http_vuln_check(port:port, url:url, pattern:">Warning<.*supplied " +
      "argument is not a valid MySQL result resource in.*product_detail.php"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
