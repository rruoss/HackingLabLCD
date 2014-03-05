##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_obm_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Open Business Management Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow the attacker to cause SQL injection
  attack, gain sensitive information and execute arbitrary HTML and script
  code in a user's browser session in the context of a vulnerable site.
  Impact Level: Application";
tag_affected = "Open Business Management (OBM) 2.4.0-rc13 and prior";
tag_insight = "Multiple vulnerabilities due to,
  - Improper access restrictions to the 'test.php' script allowing
    attackers to obtain configuration information via a direct request to
    test.php, which calls the phpinfo function.
  - Input passed via the 'sel_domain_id' and 'action' parameters to 'obm.php'
    is not properly sanitised before being used in SQL queries.
  - Input passed via the 'tf_user' parameter to group/group_index.php and
    'tf_name', 'tf_delegation', and 'tf_ip' parameters to host/host_index.php
    is not properly sanitised before being used in SQL queries.
  - Input passed to the 'tf_name', 'tf_delegation', and 'tf_ip' parameters in
    index.php, 'login' parameter in obm.php, and 'tf_user' parameter in
    group/group_index.php is not properly sanitised before being returned
    to the user.";
tag_solution = "No solution or patch is available as of 18th, September 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://obm.org/doku.php";
tag_summary = "This host is running Open Business Management and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803027);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5141", "CVE-2011-5142", "CVE-2011-5143", "CVE-2011-5144",
                "CVE-2011-5145");
  script_bugtraq_id(51153);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-18 11:33:54 +0530 (Tue, 18 Sep 2012)");
  script_name("Open Business Management Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/78009");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47139");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71924");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23060");

  script_description(desc);
  script_summary("Check if OBM is vulnerable to information disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/obm", cgi_dirs()))
{
  ## Confirm the application before trying exploit
  if(http_vuln_check(port:port, url: dir + "/obm.php", check_header: TRUE,
     pattern:"<title>.* OBM", extra_check: "OBM.org"))
  {
    ## Construct the Attack Request
    url = dir + '/test.php';

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"<title>phpinfo()",
       extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
