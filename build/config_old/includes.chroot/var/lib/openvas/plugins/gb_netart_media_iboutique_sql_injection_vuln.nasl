##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netart_media_iboutique_sql_injection_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# NetArt Media iBoutique 'key' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to conduct SQL injection.
  Impact Level: Application";
tag_affected = "NetArt Media iBoutique version 4.0";

tag_insight = "Input passed via the 'key' parameter to '/index.php' page is not properly
  verified before being used in a SQL query. This can be exploited to
  manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 23rd July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.netartmedia.net/iboutique/";
tag_summary = "This host is running NetArt Media iBoutique and is prone to
  SQL injection vulnerability.";

if(description)
{
  script_id(802442);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4039");
  script_bugtraq_id(54616);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-23 12:13:54 +0530 (Mon, 23 Jul 2012)");
  script_name("NetArt Media iBoutique 'key' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=510");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_NetArt_Media_iBoutique_SQLi_Vuln.txt");
  script_xref(name : "URL" , value : "http://antusanadi.wordpress.com/2012/07/19/netart-media-iboutique-sql-injection-vulnerability/");

  script_description(desc);
  script_summary("Check NetArt Media iBoutique SQL injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
ibPort = "";
dir = "";
sndReq = "";
rcvRes = "";

## Get HTTP port
ibPort = get_http_port(default:80);
if(!ibPort){
  ibPort = 80;
}

## Check port state
if(!get_port_state(ibPort)){
  exit(0);
}

## Check for PHP support
if(!can_host_php(port:ibPort)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/iboutique", "", cgi_dirs()))
{
  ## Request to confirm application
  sndReq = http_get(item:string(dir, "/index.php"), port:ibPort);
  rcvRes = http_keepalive_send_recv(port:ibPort, data:sndReq);

  ## Confirm application is NetArt Media iBoutique
  if(">Why iBoutique?</" >< rcvRes)
  {
    ## Construct The Attack Request
    url = string(dir, "/index.php?mod=products&key=%27");

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_hole(ibPort);
      exit(0);
    }
  }
}
