###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xpdf_mult_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xpdf Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_vuldetect = "This test uses the xpdf detection results and checks version of each binary
found on the target system. Version 3.02 and prior will raise a security
alert.";

tag_summary = "The PDF viewer Xpdf is prone to multiple vulnerabilities on Linux
systems that can lead to arbitrary code execution.";

tag_solution = "Apply Xpdf v3.02 pl3 patch: ftp://ftp.foolabs.com/pub/xpdf/xpdf-3.02pl3.patch";

tag_affected = "Xpdf version 3.02 and prior on Linux.";

tag_insight = "- Integer overflow in Xpdf JBIG2 Decoder which allows the attacker create a
malicious crafted PDF File and causes code execution.

- Flaws in Xpdf JBIG2 Decoder which causes buffer overflow, freeing of
arbitrary memory causing Xpdf application to crash.";

tag_impact = "Successful exploitation will let the attacker craft a malicious PDF File and
execute arbitrary codes into the context of the affected application to cause
denial of service attacks, buffer overflow attacks, remote code executions etc.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900457";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(34568, 34791);
  script_cve_id("CVE-2009-0195", "CVE-2009-0166", "CVE-2009-0147", "CVE-2009-0146",
                "CVE-2009-1183", "CVE-2009-1182", "CVE-2009-1181", "CVE-2009-1179",
                "CVE-2009-0800", "CVE-2009-1180", "CVE-2009-0799", "CVE-2009-0165");
  script_name("Xpdf Multiple Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34755");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=495896");
  script_xref(name : "URL" , value : "http://www.redhat.com/support/errata/RHSA-2009-0430.html");

  script_description(desc);
  script_summary("Check for the version of Xpdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_require_keys("Xpdf/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Grep for Xpdf version 3.02 and prior
ver = get_app_version(cpe:"cpe:/a:foolabs:xpdf", nvt:SCRIPT_OID);
if(version_is_less_equal(version:ver, test_version:"3.02")){
  security_hole(0);
}
