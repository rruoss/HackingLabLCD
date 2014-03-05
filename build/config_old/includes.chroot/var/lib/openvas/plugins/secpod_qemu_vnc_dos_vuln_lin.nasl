###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_qemu_vnc_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# QEMU VNC Server Denial of Service Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.

  Impact level: Application/System";

tag_solution = "Apply the available patches.
  http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=753b405331
  http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=198a0039c5

  *****
  NOTE: Ignore this warning if the above mentioned patches is already applied.
  *****";

tag_affected = "QEMU version 0.10.6 and prior on Linux.";
tag_insight = "Multiple use-after-free errors occur in 'vnc.c' in VNC server while processing
  malicious 'SetEncodings' messages sent via VNC client.";
tag_summary = "This host is running QEMU and is prone to Denial of Service
  vulnerability.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900970";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3616");
  script_bugtraq_id(36716);
  script_name("QEMU VNC Server Denial of Service Vulnerability (Linux)");
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


  script_description(desc);
  script_summary("Check for the version of QEMU");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_require_keys("QEMU/Lin/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=505641");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/10/16/8");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Grep for QEMU version <= 0.10.6
ver = get_app_version(cpe:"cpe:/a:qemu:qemu", nvt:SCRIPT_OID);
if(version_is_less_equal(version:ver, test_version:"0.10.6")){
  security_hole(0);
}
