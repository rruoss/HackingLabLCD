###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_brute_force_n_path_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# MODx Brute Force and Path Disclosure Vulnerabilities
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
tag_impact = "Successful exploitation will allow the attacker to obtain sensitive
  information that could aid in further attacks.
  Impact Level: Application";
tag_affected = "MODx CMF version 2.x (Revolution)
  MODx CMS version 1.x (Evolution)";
tag_insight = "- In login form (manager/index.php) there is no reliable protection
     from brute force attacks.
   - Insufficient error checking, allows remote attackers to obtain sensitive
     information via a direct request to a .php file, which reveals the
     installation path in an error message.";
tag_solution = "No solution or patch is available as of 21st November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://modx.com/";
tag_summary = "This host is installed with MODx and is prone to brute force and path
  disclosure vulnerabilities.";

if(description)
{
  script_id(802495);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-21 10:48:20 +0530 (Wed, 21 Nov 2012)");
  script_name("MODx Brute Force and Path Disclosure Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/142");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118240/modx-brutedisclose.txt");

  script_description(desc);
  script_summary("Check for path disclosure vulnerability in MODx CMS");
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
include("http_keepalive.inc");

port = "";

## Get HTTP port
port = get_http_port(default:80);

if(!port){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/modx", "/cmf", "",  cgi_dirs()))
{
  url = dir + "/manager/index.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, pattern:">MODx CMF Manager Login<",
     check_header:TRUE, extra_check:make_list('>MODx<', 'ManagerLogin')))
  {
    ## Construct the attack request
    url = dir + '/manager/includes/browsercheck.inc.php';

    ## Confirm the vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"Failed opening" +
       " required 'MODX_BASE_PAT.*browsercheck.inc.php", check_header:TRUE,
       extra_check:make_list('phpSniff.class.php','MODX_BASE_PATH')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
