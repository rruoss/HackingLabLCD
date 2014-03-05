##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_brekeke_pbx_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Brekeke PBX Cross-Site Request Forgery Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to change the administrator's
  password by tricking a logged in administrator into visiting a malicious
  web site.
  Impact Level: Application.";
tag_affected = "Brekeke PBX version 2.4.4.8";

tag_insight = "The flaw exists in the application which fails to perform validity checks on
  certain 'HTTP reqests', which allows an attacker to hijack the authentication
  of users for requests that change passwords via the pbxadmin.web.PbxUserEdit
  bean.";
tag_solution = "No solution or patch is available as of 31st May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.brekeke.com/";
tag_summary = "This host is running Brekeke PBX and is prone to Cross-Site Request
  Forgery Vulnerability.";

if(description)
{
  script_id(902066);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2114");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Brekeke PBX Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/64950");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39952");
  script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/05/brekeke-pbx-2448-cross-site-request.html");

  script_description(desc);
  script_summary("Check for the version of Brekeke PBX");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_require_ports("Services/www", 28080);
  script_family("Web application abuses");
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

pbxPort = get_http_port(default:28080);
if(!pbxPort){
  pbxPort = "28080";
}

if(!get_port_state(pbxPort)){
  exit(0);
}

## Send and receive response
sndReq = http_get(item:string("/pbx/gate?bean=pbxadmin.web.PbxLogin"),
                               port:pbxPort);
rcvRes = http_send_recv(port:pbxPort, data:sndReq);

## Confirm the application
if(">Brekeke PBX<" >< rcvRes)
{
  ## Grep for the version
  pbxVer = eregmatch(pattern:"Version ([0-9.]+)" , string:rcvRes);
  if(pbxVer[1] != NULL)
  {
    ## Check for Brekeke PBX version equal to 2.4.4.8
    if(version_is_equal(version:pbxVer[1], test_version:"2.4.4.8")){
      security_warning(pbxPort);
    }
  }
}
