###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for rubygem-actionpack/activerecord-2_3 openSUSE-SU-2012:0978-1 (rubygem-actionpack/activerecord-2_3)
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
tag_insight = "3 Security issues were fixed in rails 2.3 core components.

  2 NULL query issues where fixed in the actionpack gem. 1
  SQL injection was fixed in the activerecord gem.";

tag_affected = "rubygem-actionpack/activerecord-2_3 on openSUSE 12.1, openSUSE 11.4";
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
  script_xref(name : "URL" , value : "http://195.135.221.135/opensuse-security-announce/2012-08/msg00002.html");
  script_id(850307);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:42 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-2660", "CVE-2012-2694", "CVE-2012-2695");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "openSUSE-SU", value: "2012:0978_1");
  script_name("SuSE Update for rubygem-actionpack/activerecord-2_3 openSUSE-SU-2012:0978-1 (rubygem-actionpack/activerecord-2_3)");

  script_description(desc);
  script_summary("Check for the Version of rubygem-actionpack/activerecord-2_3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3", rpm:"rubygem-actionpack-2_3~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-doc", rpm:"rubygem-actionpack-2_3-doc~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-testsuite", rpm:"rubygem-actionpack-2_3-testsuite~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3", rpm:"rubygem-activerecord-2_3~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3-doc", rpm:"rubygem-activerecord-2_3-doc~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ubygem-activerecord-2_3-testsuite", rpm:"ubygem-activerecord-2_3-testsuite~2.3.14~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3", rpm:"rubygem-actionpack-2_3~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-doc", rpm:"rubygem-actionpack-2_3-doc~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-testsuite", rpm:"rubygem-actionpack-2_3-testsuite~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3", rpm:"rubygem-activerecord-2_3~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3-doc", rpm:"rubygem-activerecord-2_3-doc~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3-testsuite", rpm:"rubygem-activerecord-2_3-testsuite~2.3.14~3.8.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
