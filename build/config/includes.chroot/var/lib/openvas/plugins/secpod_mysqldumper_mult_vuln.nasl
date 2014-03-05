##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mysqldumper_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# MySQLDumper Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  script code in the context of the affected site, steal cookie based
  authentication credentials, gain sensitive information or upload arbitrary
  code.
  Impact Level: Application";
tag_affected = "MySQLDumper version 1.24.4";
tag_insight = "The flaws are due to
  - Input passed via the 'language' parameter to signin.php and 'action'
    parameter to filemanagement.php script is not properly verified before
    being used,  which allows attackers to read arbitrary files via a
    ../(dot dot) sequences.
  - Improper validation of user-supplied input passed via the 'phase' parameter
    to install.php, 'page' parameter to index.php, 'bid' parameter to sql.php
    and 'filename' parameter to restore.php,  which allows attackers to execute
    arbitrary HTML and script code.";
tag_solution = "No solution or patch is available as of 30th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer tohttp://www.mysqldumper.net/";
tag_summary = "This host is running MySQLDumper and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(902675);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4251", "CVE-2012-4252", "CVE-2012-4253",
                "CVE-2012-4254", "CVE-2012-4255");
  script_bugtraq_id(53306);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-30 15:02:29 +0530 (Mon, 30 Apr 2012)");
  script_name("MySQLDumper Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/81613");
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18146");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75283");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75284");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75285");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75286");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75287");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112304/MySQLDumper-1.24.4-LFI-XSS-CSRF-Code-Execution-Traversal.html");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in MySQLDumper");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 SecPod");
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


##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";
files = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/msd", "/mysqldumper", cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                    pattern:">MySQLDumper<", extra_check:"MySQL\_Dumper\_menu"))
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = string(dir, "/filemanagement.php?action=dl&f=",
                   crap(data:"../",length:3*15), files[file], "%00");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file, check_header:TRUE))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
