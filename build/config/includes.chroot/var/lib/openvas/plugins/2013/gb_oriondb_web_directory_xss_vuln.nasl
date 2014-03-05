###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oriondb_web_directory_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# OrionDB Web Directory Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";

tag_affected = "OrionDB Web Directory";
tag_insight = "Input passed via 'c' and 'searchtext' parameters to index.php is not
  properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 27th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.oriondb.com";
tag_summary = "This host is installed with oriondb web directory and is prone to
  cross site scripting vulnerability.";

if(description)
{
  script_id(803458);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-01 10:55:57 +0530 (Mon, 01 Apr 2013)");
  script_name("OrionDB Web Directory Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120962");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/oriondb-business-directory-script-cross-site-scripting");
  script_summary("Check if OrionDB Web Directory is vulnerable to XSS");
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
foreach dir (make_list("", "/oriondb", "/mwd", "/db", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("OrionDB Web Directory<" >< res)
  {
    ## Construct the attack request
    url = dir + "/index.php?c=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"<script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
