###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_atutor_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Atutor Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary script code
  or to compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "ATutor version 2.0.2";
tag_insight = "Multiple flaws are due to an,
  - Input passed to the 'lang' parameter in '/documentation/index_list.php' is
    not properly sanitised before being returned to the user.
  - Input passed to the 'p_course', 'name' and 'value' parameters in
    '/mods/_standard/social/set_prefs.php' scripts is not properly sanitised
    before being used in SQL queries.
  - Input passed via the 'search_friends_HASH' POST parameter, where HASH is
    the value generated by the 'rand_key' parameter, to the
    '/mods/_standard/social/index_public.php' script is not properly sanitised
    before being returned to the user.";
tag_solution = "No solution or patch is available as of 21th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to  http://www.atutor.ca/atutor/";
tag_summary = "This host is running Atutor and is prone to information disclosure,
  SQL injection, and cross site scripting vulnerabilities.";

if(description)
{
  script_id(902728);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49057);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Atutor Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17631/");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011080041");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5037.php");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103765/ZSL-2011-5037.txt");

  script_description(desc);
  script_summary("Check if Atutor is vulnerable to Cross Site Scripting");
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

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/ATutor", "/atutor", "", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/login.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("ATutor<" >< res)
  {
    rand = rand();
    xss = 'search_friends_' + rand + '=1>"><script>alert(1)</script>&search=' +
          'Search&rand_key=' + rand;
    host = get_host_name();
    filename = string(dir + "/mods/_standard/social/index_public.php");

    ## Construct post request
    sndReq2 = string( "POST ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: OpenVAs-Agent\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(xss), "\r\n\r\n",
                       xss);

    ## Check the response to confirm vulnerability
    rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);
    if('"><script>alert(1)</script>' >< rcvRes2)
    {
      security_warning(port);
      exit(0);
    }
  }
}