##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phux_download_manager_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# phux Download Manager 'file' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to cause SQL injection attack and
  gain sensitive information.
  Impact Level: Application";
tag_affected = "phux Download Manager version 0.1 and prior.";
tag_insight = "The flaw is due to an improper validation of user-supplied input
  via the 'file' parameter to download.php, which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 07th, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.inetscriptdirectory.com/company/phux-download-manager";
tag_summary = "This host is running phux Download Manager and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(802586);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0980");
  script_bugtraq_id(51725);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-07 12:53:59 +0530 (Tue, 07 Feb 2012)");
  script_name("phux Download Manager 'file' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18432/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51725/info");

  script_description(desc);
  script_summary("Check if phux Download Manager is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Variable Initialisation
dir = "";
port = 0;
sndReq = "";
rcvRes = NULL;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Check for possible names
foreach dir (make_list("", "/download_manager", "/phux", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(!isnull(rcvRes) && ">phux.org's<" >< rcvRes &&
                        "Public Download Center<" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/download.php?file='";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"mysql_num_rows\(\): " +
                          "supplied argument is not a valid MySQL"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
