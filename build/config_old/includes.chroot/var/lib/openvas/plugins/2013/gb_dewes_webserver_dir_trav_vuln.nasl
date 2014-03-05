##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dewes_webserver_dir_trav_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Twilight CMS DeWeS Web Server Directory Traversal Vulnerability
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

if(description)
{
  script_id(803746);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4900");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-22 12:47:40 +0530 (Thu, 22 Aug 2013)");
  script_name("Twilight CMS DeWeS Web Server Directory Traversal Vulnerability");

  tag_summary =
"The host is running Twilight CMS with DeWeS Web Server and is prone to directory
traversal vulnerability.";

  tag_vuldetect =
"Send the crafted HTTP GET request and check the is it possible to read
the system file.";

  tag_insight =
"The flaw is due to an improper sanitation of encoded user input via HTTP
requests using directory traversal attack (e.g., /..%5c..%5c).";

  tag_impact =
"Successful exploitation will allow attackers to read arbitrary files
on the target system.

  Impact Level: Application";

  tag_affected =
"Twilight CMS DeWeS web server version 0.4.2 and prior.";

  tag_solution =
"No solution or patch is available as of 19th September, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.stratek.ru";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/96479");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/136");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23167");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/528139/30/0/threaded");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/dewes-042-path-traversal");
  script_summary("Check if Twilight CMS DeWeS web server is vulnerable to directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
files = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the application
banner = get_http_banner(port:port);
if("Server: DeWeS" >!< banner){
  exit(0);
}

files = traversal_files();
foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = "/" + crap(data:"..%5c",length:15) + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_warning(port:port);
    exit(0);
  }
}
