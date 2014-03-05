###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# HTTP File Server Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow an attacker to insert arbitrary HTML and
  script code and execute arbitrary PHP code.
  Impact Level: Application";

tag_affected = "HttpFileServer version 2.2f and prior";
tag_insight = "- An input passed to 'search' parameter is not properly sanitized before
    being returned to the user.
  - An error due to the '~upload ' script allowing the upload of files with
    arbitrary extensions to a folder inside the webroot can be exploited to
    execute arbitrary PHP code by uploading a malicious PHP script.";
tag_solution = "No solution or patch is available as of 19th February, 2013. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.rejetto.com/hfs/";
tag_summary = "This host is running HTTP File Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803171);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-19 15:17:57 +0530 (Tue, 19 Feb 2013)");
  script_name("HTTP File Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20345");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2013/02/http-file-server-v2x-xss-and-file.html");

  script_description(desc);
  script_summary("Check the HttpFileServer version <= 2.2f");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
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
include("version_func.inc");
include("http_keepalive.inc");

port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);

if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: HFS" >!< banner) {
  exit(0);
}

## Match the version from banner
vers = eregmatch(pattern:"Server: HFS (([0-9.])+([a-z]+)?)", string:banner);
if(isnull(vers[1])){
  exit(0);
}

##Check the vulnerable versions
if(version_is_less_equal(version:vers[1], test_version:"2.2f"))
{
  security_hole(port:port);
  exit(0);
}
