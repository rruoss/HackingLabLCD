###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_multiple_vuln_may11.nasl 13 2013-10-27 12:16:33Z jan $
#
# SmarterMail Multiple Vulnerabilities May-11
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_insight = "Multiple flaws are present in the application. More detail is available at,

  http://xss.cx/examples/smarterstats-60-oscommandinjection-directorytraversal-xml-sqlinjection.html.html";

tag_impact = "Successful exploitation could allow attackers to conduct cross site scripting,
  command execution and directory traversal attacks.
  Impact Level: Application";
tag_affected = "SmarterTools SmarterMail versions 6.0 and prior.";
tag_solution = "Upgrade to SmarterTools SmarterMail 8.0 or later,
  For updates refer to http://www.smartertools.com/smartermail/mail-server-software.aspx";
tag_summary = "This host is running SmarterMail and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902432);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2011-2148", "CVE-2011-2149", "CVE-2011-2150", "CVE-2011-2151",
                "CVE-2011-2152", "CVE-2011-2153", "CVE-2011-2154", "CVE-2011-2155",
                "CVE-2011-2156", "CVE-2011-2157", "CVE-2011-2158", "CVE-2011-2159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SmarterMail Multiple Vulnerabilities May-11");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/240150");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/MORO-8GYQR4");
  script_xref(name : "URL" , value : "http://xss.cx/examples/smarterstats-60-oscommandinjection-directorytraversal-xml-sqlinjection.html.html");

  script_description(desc);
  script_summary("Verify multiple vulnerabilities in SmarterMail");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_keys("SmartMail/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("http_func.inc");

smPort = "9998";
if(!get_port_state(smPort)){
  exit(0);
}

## Check the banner
smBanner = get_http_banner(port:smPort);
if(!smBanner){
  exit(0);
}

sndReq = http_get(item:"/Login.aspx", port:smPort);
rcvRes = http_send_recv(port:smPort, data:sndReq);

## Confirm the application
if("SmarterMail Login - SmarterMail" >< rcvRes)
{
  ## Construct attack request
  sndReq = http_get(item:"/Login.aspx?shortcutLink=autologin&txtSiteID" +
                         "=admin&txtUser=admin&txtPass=admin", port:smPort);
  rcvRes = http_send_recv(port:smPort, data:sndReq);

  ## Check the working exploit
  if("txtUser=admin&" >< rcvRes && "txtPass=admin" >< rcvRes){
    security_hole(smPort);
  }
}
