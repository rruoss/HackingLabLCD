###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_admanager_plus_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine ADManager Plus Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "ManageEngine ADManager Plus version 5.2 Build 5210";
tag_insight = "The flaw is due to an input passed to the 'domainName' parameter in
  jsp/AddDC.jsp and 'operation' POST parameter in DomainConfig.do (when
  'methodToCall' is set to 'save') is not properly sanitised before being
  returned to the user.";
tag_solution = "No solution or patch is available as of 8th, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.co.in/products/ad-manager/download.html";
tag_summary = "This host is running Zoho ManageEngine ADManager Plus and is prone
  to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(802587);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1049");
  script_bugtraq_id(51893);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-08 12:14:53 +0530 (Wed, 08 Feb 2012)");
  script_name("Zoho ManageEngine ADManager Plus Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47887/");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/codes/admanager_xss.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109528/ZSL-2012-5070.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5070.php");

  script_description(desc);
  script_summary("Check if Zoho ManageEngine ADManager Plus is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
port = 0;
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

if(!get_port_state(port)) {
  exit(0);
}

sndReq = "";
rcvRes = "";
sndReq = http_get(item:"/home.do", port:port);
if(!isnull(sndReq))
{
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(!isnull(rcvRes) && "<title>ManageEngine - ADManager Plus</title>" >< rcvRes)
  {
    ## Construct attack
    url = '/jsp/AddDC.jsp?domainName="><script>alert(document.cookie)</script>';

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(" +
                                    "document.cookie\)</script>")){
      security_warning(port:port);
    }
  }
}
