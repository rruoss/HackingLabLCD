##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orbis_cms_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Orbis CMS 'editor-body.php' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "Orbis CMS version 1.0.2 and prior";

tag_insight = "The flaw is due to an input passed via the 's' parameter to
  'admin/editors/text/editor-body.php', which is not properly sanitised before
  being returned to the user.";
tag_solution = "No solution or patch is available as of 13th July 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.novo-ws.com/orbis-cms/download.shtml";
tag_summary = "This host is running Orbis CMS and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(801404);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-2669");
  script_bugtraq_id(41390);
  script_name("Orbis CMS 'editor-body.php' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40474");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60087");

  script_description(desc);
  script_summary("Check Orbis CMS is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orbis_cms_detect.nasl");
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

## Get HTTP Port
orbisPort = get_http_port(default:80);
if(!get_port_state(orbisPort)){
  exit(0);
}

## Get Orbis CMS Path from KB
if(!dir = get_dir_from_kb(port:orbisPort, app:"Orbis/CMS/Ver")){
 exit(0);
}

# Try expliot and check response
sndReq = http_get(item:string(dir, '/admin/editors/text/editor-body.php?' +
                 's="><script>alert(123456789)</script>"'), port:orbisPort);
rcvRes = http_send_recv(port:orbisPort, data:sndReq);
if("123456789" >< rcvRes){
  security_warning(orbisPort);
}
