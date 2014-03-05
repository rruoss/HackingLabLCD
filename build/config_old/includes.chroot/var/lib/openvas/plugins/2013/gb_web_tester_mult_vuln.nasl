###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_web_tester_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WebTester Multiple Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804027";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-16 12:57:49 +0530 (Wed, 16 Oct 2013)");
  script_name("WebTester Multiple Vulnerabilities");

  tag_summary =
"This host is running WebTester and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to read sensitive
information or not.";

  tag_insight =
"Multiple flaws are due to,
- Input passed via 'TestID' parameter to 'startTest.php' script is not properly
  sanitized before being used in the code.
- The application is not verifying permissions when accessing certain files
  like phpinfo.php and '/tiny_mce/plugins/filemanager/InsertFile/insert_file.php'
- Application is not removing installed files after installation.";

  tag_impact =
"Successful exploitation will allow remote attackers to manipulate SQL queries
by injecting arbitrary SQL code, Upload arbitrary file, and disclose sensitive
information.

Impact Level: Application";

  tag_affected =
"WebTester version 5.x, Other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 16th October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://sourceforge.net/projects/webtesteronline";

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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/21384");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123629");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/webtester-5x-sql-injection-file-upload-disclosure");
  script_summary("Check if WebTester is prone to information disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list("", "/webtester", "/webtester5", "/tester", cgi_dirs()))
{
  ## Confirm the Application
  if(http_vuln_check(port:http_port, url:string(dir,"/index.php"),
                                check_header:TRUE,
                                pattern:">WebTester"))
  {
    url = dir + '/phpinfo.php';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:">phpinfo\(\)<", extra_check:">Configuration File"))
    {
      security_hole(http_port);
      exit(0);
    }
  }
}
