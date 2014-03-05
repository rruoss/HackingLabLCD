##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_movable_type_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Movable Type Multiple Vulnerabilities
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to gain knowledge of sensitive
  information or inject SQL queries.
  Impact Level: Application.";
tag_affected = "Movable Type version 4.x before 4.35 and 5.x before 5.04";

tag_insight = "Multiple flaws are caused by input validation errors related to
  'mt:AssetProperty' and 'mt:EntryFlag' tags and in dynamic publishing error
  messages, which could be exploited to conduct SQL injection or cross site
  scripting attacks.";
tag_solution = "Upgarde Movable Type to 4.35 and 5.04 or later,
  For updates refer to http://www.movabletype.org/";
tag_summary = "This host is running movable type and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902402";
CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2010-3921", "CVE-2010-3922", "CVE-2010-4509", "CVE-2010-4511");
  script_bugtraq_id(45380, 45383, 45250, 45253);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Movable Type Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/69751");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42539");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3145");
  script_xref(name : "URL" , value : "http://www.movabletype.org/documentation/appendices/release-notes/movable-type-504-435-release-notes.html");

  script_description(desc);
  script_summary("Check for the version of Movable Type");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("mt_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("movabletype/installed");
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
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!mtVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Check for vulnerable version.
if(version_in_range(version: mtVer, test_version:"4.0", test_version2:"4.34") ||
   version_in_range(version: mtVer, test_version:"5.0", test_version2:"5.03")){
  security_hole(port:port);
}
