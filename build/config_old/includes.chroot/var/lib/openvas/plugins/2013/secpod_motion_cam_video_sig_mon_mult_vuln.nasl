###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_motion_cam_video_sig_mon_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Motion Camera Video Signal Monitor Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site,
  and cause denial of service condition.
  Impact Level: Application";

tag_affected = "Motion version 3.2.12";
tag_insight = "Multiple flaws are due to,
  - Improper validation of user supplied to the motion binary via 'pid' and
    'filename' parameters.
  - Input passed via 'process_id_file', 'control_authentication' and 'sql_query'
    parameters to /config/set page is not properly sanitized before being
    returned to the user.";
tag_solution = "No solution or patch is available as of 28th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/motion";
tag_summary = "This host is installed with Motion Video Signal Monitor and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(903313);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-28 10:45:03 +0530 (Fri, 28 Jun 2013)");
  script_name("Motion Camera Video Signal Monitor Multiple Vulnerabilities");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122171/motion3212-sqlxssxsrfoverflow.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/motion-3212-xss-csrf-buffer-overflow-sql-injection");
  script_summary("Check if Motion Video Signal Monitor is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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

# Variable Initialization
port = "";
dir = "";
url = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
 port = 8080;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Application Confirmation
if(http_vuln_check(port:port, url: "/",
   pattern:">Motion", check_header:TRUE, extra_check:">All<"))
{
  ## Construct attack request
  url = "/0/config/set?process_id_file=</li><script>alert(document.cookie);</script><li>";

  ## Check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document.cookie\);</script>",
     extra_check:">process_id_file"))
  {
    security_hole(port);
    exit(0);
  }
}
