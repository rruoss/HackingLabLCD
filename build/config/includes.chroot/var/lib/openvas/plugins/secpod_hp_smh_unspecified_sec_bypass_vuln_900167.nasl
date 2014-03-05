##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_unspecified_sec_bypass_vuln_900167.nasl 16 2013-10-27 13:09:52Z jan $
# Description: HP SMH Unspecified Security Bypass Vulnerability
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
tag_summary = "The host is running System Management Homepage and is prone to
  local security bypass vulnerability.

  The flaw is caused by an unspecified error, which can be exploited by
  local users to perform certain actions with escalated privileges.";

tag_solution = "Update to HP SMH version 2.2.9.1 or subsequent
  http://software.hp.com

  *****
  NOTE: Ignore this warning, if OS is other than HP-UX B.11.11 and B.11.23,
        HP-UX B.11.23 and B.11.31.
  *****";

tag_impact = "Attackers can leverage this issue to gain local unauthorized access.
  Impact Level: Application";
tag_affected = "HP SMH version 2.2.6 and prior on HP-UX B.11.11 and B.11.23
  HP SMH version 2.2.6 and 2.2.8 and prior on HP-UX B.11.23 and B.11.31";

if(description)
{
  script_id(900167);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_bugtraq_id(32088);
  script_cve_id("CVE-2008-4413");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("HP SMH Unspecified Security Bypass Vulnerability");
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

  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-4413");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01586921");

  script_description(desc);
  script_dependencies("http_version.nasl","os_fingerprint.nasl","gb_snmp_os_detection.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

if (host_runs("hp-ux") != "yes") exit(0);

smhPort = 2301;
if(get_port_state(smhPort))
{
  smhReq = http_get(item:"/", port:smhPort);
  smhRes = http_send_recv(port:smhPort, data:smhReq);
  if(egrep(pattern:"CompaqHTTPServer/9\.9 HP System Management Homepage",
     string:smhRes) && egrep(pattern:"^HTTP/.* 302 Found", string:smhRes))
  {
    # Grep the versions < 2.2.9.1
    pattern = "/[01](\..*)|2.([01](\..*)?|2(\.[0-8](\..*)?|\.9\.0)?)($|[^.0-9])";
    if(egrep(pattern:pattern, string:smhRes)){
       security_hole(0);
    }
  }
}
