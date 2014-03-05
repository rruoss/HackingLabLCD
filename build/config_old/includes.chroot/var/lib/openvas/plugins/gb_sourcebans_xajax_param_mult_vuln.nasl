###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sourcebans_xajax_param_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SourceBans 'xajax' Parameter Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to perform SQL injection attack
  or directory traversal attacks and gain sensitive information.
  Impact Level: Application";
tag_affected = "SourceBans versions 1.4.8 and prior.";
tag_insight = "Multiple flaws are due to improper validation of input passed via
  the parameter 'xajax' to index.php script before being used in SQL queries.
  Which can be exploited to read and delete an arbitrary file.";
tag_solution = "No solution or patch is available as of 8th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sourcebans.net/";
tag_summary = "The host is running SourceBan and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802354);
  script_version("$Revision: 13 $");
  script_bugtraq_id(50948);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-08 12:15:24 +0530 (Thu, 08 Dec 2011)");
  script_name("SourceBans 'xajax' Parameter Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47080");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71669");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71670");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18215/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107589/sourcebans-lfisql.txt");

  script_description(desc);
  script_summary("Check if SourceBans is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
foreach dir (make_list("/sourcebans", "/sb", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if(">SourceBans" >< res)
  {
    ## Construct the SQL attack
    url = dir + "/index.php?xajax=RefreshServer&xajaxargs[]=1'";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"You have an error in your SQL syntax;",
                       extra_check:"SQL Query type:"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
