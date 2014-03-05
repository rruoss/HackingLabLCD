###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for xine-lib MDVSA-2008:178 (xine-lib)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

include("revisions-lib.inc");
tag_insight = "Alin Rad Pop found an array index vulnerability in the SDP parser
  of xine-lib.  If a user or automated system were tricked into opening
  a malicious RTSP stream, a remote attacker could possibly execute
  arbitrary code with the privileges of the user using the program
  (CVE-2008-0073).

  The ASF demuxer in xine-lib did not properly check the length of
  ASF headers.  If a user was tricked into opening a crafted ASF file,
  a remote attacker could possibly cause a denial of service or execute
  arbitrary code with the privileges of the user using the program
  (CVE-2008-1110).
  
  The Matroska demuxer in xine-lib did not properly verify frame sizes,
  which could possibly lead to the execution of arbitrary code if a
  user opened a crafted ASF file (CVE-2008-1161).
  
  Luigi Auriemma found multiple integer overflows in xine-lib.  If a
  user was tricked into opening a crafted FLV, MOV, RM, MVE, MKV, or
  CAK file, a remote attacker could possibly execute arbitrary code
  with the privileges of the user using the program (CVE-2008-1482).
  
  Guido Landi found A stack-based buffer overflow in xine-lib
  that could allow a remote attacker to cause a denial of service
  (crash) and potentially execute arbitrary code via a long NSF title
  (CVE-2008-1878).
  
  The updated packages have been patched to correct this issue.";

tag_affected = "xine-lib on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-08/msg00021.php");
  script_id(830768);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2008:178");
  script_cve_id("CVE-2008-0073", "CVE-2008-1110", "CVE-2008-1161", "CVE-2008-1482", "CVE-2008-1878");
  script_name( "Mandriva Update for xine-lib MDVSA-2008:178 (xine-lib)");

  script_description(desc);
  script_summary("Check for the Version of xine-lib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libxine1", rpm:"libxine1~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxine-devel", rpm:"libxine-devel~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-aa", rpm:"xine-aa~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-caca", rpm:"xine-caca~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-dxr3", rpm:"xine-dxr3~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-esd", rpm:"xine-esd~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-flac", rpm:"xine-flac~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-gnomevfs", rpm:"xine-gnomevfs~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-image", rpm:"xine-image~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-jack", rpm:"xine-jack~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-plugins", rpm:"xine-plugins~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-pulse", rpm:"xine-pulse~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-sdl", rpm:"xine-sdl~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-smb", rpm:"xine-smb~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xine1", rpm:"lib64xine1~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xine-devel", rpm:"lib64xine-devel~1.1.8~4.7mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
