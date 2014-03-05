##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_com_video_gallery_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Joomla! 'Video Gallery' Component Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and read arbitrary files via directory
  traversal attacks and gain sensitive information.
  Impact Level: Application";
tag_affected = "Joomla! Video Gallery Component";
tag_insight = "Multiple flaws are due to
  - Input passed via the 'Itemid' parameter to index.php script is not
    properly sanitised before being used in SQL queries.
  - Improper validation of user-supplied input passed via the 'controller'
    parameter to 'index.php', which allows attackers to read arbitrary files
    via ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 25th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/extensions/";
tag_summary = "This host is running Joomla! Video Gallery component and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(902673);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-25 18:38:13 +0530 (Wed, 25 Apr 2012)");
  script_name("Joomla! 'Video Gallery' Component Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18125");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112161/joomlavideogallery-lfisql.txt");

  script_description(desc);
  script_summary("Check if Joomla! Video Gallery is vulnerable to SQL injection");
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

## Construct attack request
url = joomlaDir + "/index.php?option=com_videogallery&Itemid='";

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
   pattern:"You have an error in your SQL syntax;")){
  security_hole(joomlaPort);
}
