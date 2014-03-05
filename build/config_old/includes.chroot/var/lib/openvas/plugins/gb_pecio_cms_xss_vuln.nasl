###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pecio_cms_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# pecio cms 'target' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  code in a user's browser session in the context of a vulnerable application.
  Impact Level: Application.";
tag_affected = "Pecio CMS v2.0.5 and prior.";
tag_insight = "Input passed via the 'target' parameter in 'search' action in index.php is
  not properly verified before it is returned to the user. This can be exploited
  to execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site. This may allow an attacker to steal cookie-based
  authentication credentials and launch further attacks.";
tag_solution = "No solution or patch is available as of 23rd November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://pecio-cms.com/article/downloads";
tag_summary = "The host is running Pecio CMS and is prone to Cross-Site Scripting
  vulnerability.";

if(description)
{
  script_id(801544);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(44304);
  script_name("Pecio CMS 'target' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://pecio-cms.com/");
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=137");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514404");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_pecioCMS_XSS.txt");

  script_description(desc);
  script_summary("Check for the Cross-Site Scripting vulnerability Pecio CMS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks");
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
include("http_keepalive.inc");

pcmsPort = get_http_port(default:80);
if(!pcmsPort){
  exit(0);
}

foreach dir (make_list("/pecio-2.0.5","/pecio-cms"))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:pcmsPort);
  rcvRes = http_send_recv(port:pcmsPort, data:sndReq);

  ## Confirm the application
  if(">pecio homepage</" >< rcvRes)
  {
    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:pcmsPort, url:dir + "/index.php?target=search&" +
                       "term=<script>alert('XSS-Test')</script>",
                       pattern:"(<script>alert.'XSS-Test'.</script>)"))
    {
      security_warning(port:pcmsPort);
      exit(0);
    }
  }
}
