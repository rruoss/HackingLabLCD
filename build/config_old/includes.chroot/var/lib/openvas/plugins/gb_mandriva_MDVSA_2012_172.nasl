###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for libproxy MDVSA-2012:172 (libproxy)
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
tag_insight = "A vulnerability has been discovered and corrected in libproxy:

  Stack-based buffer overflow in the url::get_pac function in url.cpp
  in libproxy 0.4.x before 0.4.9 allows remote servers to have an
  unspecified impact via a large proxy.pac file (CVE-2012-4504).

  The updated packages have been patched to correct this issue.";

tag_affected = "libproxy on Mandriva Linux 2011.0";
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
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:172");
  script_id(831751);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-11-23 12:00:04 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-4504");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2012:172");
  script_name("Mandriva Update for libproxy MDVSA-2012:172 (libproxy)");

  script_description(desc);
  script_summary("Check for the Version of libproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libmodman1", rpm:"libmodman1~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy1", rpm:"libproxy1~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-gnome", rpm:"libproxy-gnome~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-kde", rpm:"libproxy-kde~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-networkmanager", rpm:"libproxy-networkmanager~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-perl", rpm:"libproxy-perl~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libproxy-utils", rpm:"libproxy-utils~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libproxy", rpm:"python-libproxy~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64modman1", rpm:"lib64modman1~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64proxy1", rpm:"lib64proxy1~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64proxy-devel", rpm:"lib64proxy-devel~0.4.6~5.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
