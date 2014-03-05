###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libtiff CESA-2012:1590 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  A heap-based buffer overflow flaw was found in the way libtiff processed
  certain TIFF images using the Pixar Log Format encoding. An attacker could
  create a specially-crafted TIFF file that, when opened, could cause an
  application using libtiff to crash or, possibly, execute arbitrary code
  with the privileges of the user running the application. (CVE-2012-4447)
  
  A stack-based buffer overflow flaw was found in the way libtiff handled
  DOTRANGE tags. An attacker could use this flaw to create a
  specially-crafted TIFF file that, when opened, would cause an application
  linked against libtiff to crash or, possibly, execute arbitrary code.
  (CVE-2012-5581)
  
  A heap-based buffer overflow flaw was found in the tiff2pdf tool. An
  attacker could use this flaw to create a specially-crafted TIFF file that
  would cause tiff2pdf to crash or, possibly, execute arbitrary code.
  (CVE-2012-3401)
  
  A missing return value check flaw, leading to a heap-based buffer overflow,
  was found in the ppm2tiff tool. An attacker could use this flaw to create a
  specially-crafted PPM (Portable Pixel Map) file that would cause ppm2tiff
  to crash or, possibly, execute arbitrary code. (CVE-2012-4564)
  
  The CVE-2012-5581, CVE-2012-3401, and CVE-2012-4564 issues were discovered
  by Huzaifa Sidhpurwala of the Red Hat Security Response Team.
  
  All libtiff users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. All running applications linked
  against libtiff must be restarted for this update to take effect.";

tag_affected = "libtiff on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-December/019038.html");
  script_id(881551);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-26 12:06:35 +0530 (Wed, 26 Dec 2012)");
  script_cve_id("CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2012:1590");
  script_name("CentOS Update for libtiff CESA-2012:1590 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of libtiff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.9.4~9.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.9.4~9.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~3.9.4~9.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}