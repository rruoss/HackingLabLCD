###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_todayu_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Todayu Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation could allow execution of scripts or actions
  written by an attacker. In addition, an attacker may obtain authorization
  cookies that would allow him to gain unauthorized access to the application.
  Impact Level: Application";
tag_affected = "Todayu version 2.1.0 and prior";
tag_insight = "The flaw is due to failure in the 'lib/js/jscalendar/php/test.php?'
  script to properly sanitize user supplied input in 'lang' parameter.";
tag_solution = "No solution or patch is available as of 25th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.todoyu.com/community/download/";
tag_summary = "This host is running Todayu and is prone to cross site scripting
  vulnerabilities.";

if(description)
{
  script_id(902416);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Todayu Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100695/Todoyu2.0.8-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityhome.eu/exploits/exploit.php?eid=14706246374db10bfe6f4f71.12853295");

  script_description(desc);
  script_summary("Check if Todayu is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/todayu", "/Todoyu", "/"))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("<title>Login - todoyu</title>" >< res)
  {
    req = http_get(item:string(dir, '/lib/js/jscalendar/php/test.php?lang="' +
                    '></script><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if('<script>alert("XSS-TEST")</script>' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
