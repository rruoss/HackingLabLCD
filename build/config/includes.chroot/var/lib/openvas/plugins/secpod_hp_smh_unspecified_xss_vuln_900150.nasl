##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_unspecified_xss_vuln_900150.nasl 16 2013-10-27 13:09:52Z jan $
# Description: HP System Management Homepage Unspecified XSS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "An attacker can execute arbitrary script code in the user's browser session.

  Impact Level : Application";

tag_solution = "Update to version 2.1.15.210 or later.
  HP System Management Homepage for Linux (x86) v2.1.15.210:
  http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-e85a4029b2dd42959f1f82dda7

  HP System Management Homepage for Linux (AMD64/EM64T) v2.1.15.210:
  http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-5c90113499bb41faacdcad9485  

  HP System Management Homepage for Windows v2.1.15.210:
  http://h20000.www2.hp.com/bizsupport/TechSupport/SoftwareDescription.jsp?swItem=MTX-84b4161b7cd3455fb34ac57586";

tag_summary = "The host is running HP System Management Homepage, which is prone
  to unspecified XSS Vulnerability. 

  Certain input parameters are not properly sanitized before returned to the
  user.";

tag_affected = "HP System Management Homepage versions prior to 2.1.15.210";

if(description)
{
  script_id(900150);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:57:31 +0200 (Tue, 14 Oct 2008)");
  script_bugtraq_id(31663);
  script_cve_id("CVE-2008-4411");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("HP System Management Homepage Unspecified XSS Vulnerability");
  script_summary("Check for vulnerable version of HP SMH");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_description(desc);
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32199/");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01570589");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

smhPort = 2301;
if(get_port_state(smhPort))
{
  smhReq = http_get(item:"/", port:smhPort);
  smhRes = http_keepalive_send_recv(port:smhPort, data:smhReq);

  if(egrep(pattern:"CompaqHTTPServer/9\.9 HP System Management Homepage", 
     string:smhRes) && egrep(pattern:"^HTTP/.* 302 Found", string:smhRes))
  {
    if(egrep(pattern:"/2\.(0(\..*)?|1((\.[0-9]|\.1[0-5])(\.[01]?[0-9]?[0-9]|" +
                     "\.20[0-9])?)?)($|[^.0-9])", string:smhRes)){
       security_warning(smhPort);
    }
  }
}
