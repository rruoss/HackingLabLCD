##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# WampServer 'lang' Parameter Cross-site Scripting (XSS) Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  application.
  Impact Level: Application.";
tag_affected = "WampServer version 2.0i";

tag_insight = "Input passed to the 'lang' parameter in index.php is not properly sanitised
  before being returned to the user.";
tag_solution = "No solution or patch is available as of 26th February 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wampserver.com/en/index.php";
tag_summary = "This host is running WampServer is prone to Cross-Site Scripting
  vulnerability.";

if(description)
{
  script_id(800298);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(38357);
  script_cve_id("CVE-2010-0700");
  script_name("WampServer 'lang' Parameter Cross-site Scripting (XSS) Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38706");
  script_xref(name : "URL" , value : "http://zeroscience.mk/codes/wamp_xss.txt");
  script_xref(name : "URL" , value : "http://zeroscience.mk/en/vulnerabilities/ZSL-2010-4926.php");

  script_description(desc);
  script_summary("Check for the version of WampServer");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

wampPort = get_http_port(default:80);
if(!wampPort){
  exit(0);
}

## Check Wamp Server is running
wampVer = get_kb_item("www/" + wampPort + "/WampServer");
if(!wampVer){
  exit(0);
}

## Construct Crafted(XSS) Requested
sndReq = http_get(item:string("/index.php?lang=<script>alert('OpenVAS_XSS_" +
                              "Testing')</script>"), port:wampPort);
rcvRes = http_send_recv(port:wampPort, data:sndReq);

## Check OpenVAS XSS Testing is present in the response
if("OpenVAS_XSS_Testing" >< rcvRes)
{
  security_warning(wampPort);
  exit(0);
}
