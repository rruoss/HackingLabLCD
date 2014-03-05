###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_mult_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenSC Smart Card Serial Number Multiple Buffer Overflow Vulnerabilities (Win)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause denial
  of service conditions.
  Impact Level: Application";
tag_affected = "OpenSC version 0.11.13 and prior.";
tag_insight = "The flaws are due to boundary errors in the 'acos_get_serialnr()',
  'acos5_get_serialnr()', and 'starcos_get_serialnr()' functions when reading
  out the serial number of smart cards.";
tag_solution = "Upgrade to OpenSC 0.12.0 or later.
  For updates refer to http://www.opensc-project.org/opensc";
tag_summary = "This host is installed with OpenSC and is prone to multiple buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(901175);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4523");
  script_bugtraq_id(45435);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("OpenSC Smart Card Serial Number Multiple Buffer Overflow Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42658");
  script_xref(name : "URL" , value : "https://www.opensc-project.org/opensc/changeset/4913");
  script_xref(name : "URL" , value : "http://labs.mwrinfosecurity.com/files/Advisories/mwri_opensc-get-serial-buffer-overflow_2010-12-13.pdf");

  script_description(desc);
  script_summary("Check for the version of OpenSC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_require_keys("OpenSC/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
oscVer = get_kb_item("OpenSC/Win/Ver");

## Check for OpenSC version 0.11.13 and prior
if(version_is_less_equal(version:oscVer, test_version:"0.11.13")) {
  security_hole(0);
}
