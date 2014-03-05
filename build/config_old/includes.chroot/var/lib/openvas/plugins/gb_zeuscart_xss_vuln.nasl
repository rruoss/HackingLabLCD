###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zeuscart_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# ZeusCart 'search' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks.
  Impact Level: Application";
tag_affected = "ZeusCart Versions 3.0 and 2.3.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'search' parameter in a 'search' action which allows attacker to execute
  arbitrary HTML and script code in a user's browser session.";
tag_solution = "No solution or patch is available as of 09th August, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.zeuscart.com/";
tag_summary = "The host is running ZeusCart and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(801249);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("ZeusCart 'search' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=109");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35319/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512885");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_ZeusCart_XSS.txt");

  script_description(desc);
  script_summary("Determine if ZeusCart is prone to XSS Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zeuscart_detect.nasl");
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
zcPort = get_http_port(default:80);
if(!zcPort){
  exit(0);
}

## Get version and directory from KB
zcVer = get_version_from_kb(port:zcPort, app:"ZeusCart");
zcDir = get_dir_from_kb(port:zcPort, app:"ZeusCart");
if(!zcVer || !zcDir) {
  exit(0);
}

if(!safe_checks())
{
  ## Construct attack request
  zcReq = http_post(port:zcPort, item:string(zcDir,"/"),
                  data:"%22%20style=x:expression(alert(document.cookie))><");
  zcRes = http_keepalive_send_recv(port:zcPort, data:zcReq, bodyonly:TRUE);

  ## Confirm exploit worked by checking the response
  if(('style=x:expression(alert(document.cookie))' >< zcRes))
  {
    security_warning(zcPort);
    exit(0);
  }
}

if(version_is_equal(version:zcVer, test_version:"3.0") ||
   version_is_equal(version:zcVer, test_version:"2.3")){
    security_warning(zcPort);
}
