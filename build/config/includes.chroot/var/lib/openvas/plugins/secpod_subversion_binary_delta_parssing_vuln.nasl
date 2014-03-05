###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_subversion_binary_delta_parssing_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Subversion Binary Delta Processing Multiple Integer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_solution = "Apply the patch or Upgrade to Subversion version 1.5.7 or 1.6.4
  http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt
  http://subversion.tigris.org/project_packages.html

  *****
  NOTE: Please ignore this warning if the patch is applied.
  *****";

tag_impact = "Attackers can exploit these issues to compromise an application using the library
  or crash the application, resulting into a denial of service conditions.
  Impact Level: Application";
tag_affected = "Subversion version 1.5.6 and prior
  Subversion version 1.6.0 through 1.6.3";
tag_insight = "The flaws are due to input validation errors in the processing of svndiff
  streams in the 'libsvn_delta' library.";
tag_summary = "The host is installed with Subversion and is prone to
  multiple Integer Overflow Vulnerabilities.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.101104";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_name("Subversion Binary Delta Processing Multiple Integer Overflow Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36184/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Aug/1022697.html");
  script_xref(name : "URL" , value : "http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt");

  script_description(desc);
  script_summary("Check for the version of Subversion");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_subversion_detect.nasl");
  script_require_keys("Subversion/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:subversion:subversion", nvt:SCRIPT_OID);
if(version_is_less(version:ver, test_version:"1.5.7")||
   version_in_range(version:ver, test_version:"1.6",test_version2:"1.6.3")){
   security_hole(0);
}
