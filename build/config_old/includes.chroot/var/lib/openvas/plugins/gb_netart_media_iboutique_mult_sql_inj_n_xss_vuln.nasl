##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netart_media_iboutique_mult_sql_inj_n_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to conduct SQL injection and
  cross-site scripting attacks.
  Impact Level: Application.";
tag_affected = "NetArt Media iBoutique version 4.0";

tag_insight = "Multiple flaws are due to an,
  - Input passed to the 'cat' and 'key'  parameter in index.php (when 'mod'
    is set to 'products') is not properly sanitised before being used in a
    SQL query.
  - Input passed to the 'page' parameter in index.php is not properly sanitised
    before being used in a SQL query.

  This can further be exploited to conduct cross-site scripting attacks
  via SQL error messages.";

tag_solution = "No solution or patch is available as of 14th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.netartmedia.net/iboutique/";
tag_summary = "This host is running NetArt Media iBoutique and is prone to multiple
  SQL injection and cross-site scripting vulnerabilities.";

if(description)
{
  script_id(802404);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-5020");
  script_bugtraq_id(41014);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-14 13:46:57 +0530 (Mon, 14 Nov 2011)");
  script_name("NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6444");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31871");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13945/");

  script_description(desc);
  script_summary("Check NetArt Media iBoutique SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");


## Get HTTP port
ibPort = get_http_port(default:80);
if(!ibPort){
  exit(0);
}

if(!can_host_php(port:ibPort)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/iboutique", cgi_dirs()))
{
  ##Request to confirm application
  sndReq = http_get(item:string(dir, "/index.php"), port:ibPort);
  rcvRes = http_keepalive_send_recv(port:ibPort, data:sndReq);

  ## Confirm application is NetArt Media Car Portal
  if(">Why iBoutique?</" >< rcvRes)
  {
    ## Construct The Attack Request
    url = string(dir, "/index.php?page='");

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_hole(ibPort);
      exit(0);
    }
  }
}
