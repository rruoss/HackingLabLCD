###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for freetype2 openSUSE-SU-2012:0047-1 (freetype2)
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
tag_affected = "freetype2 on openSUSE 11.4, openSUSE 11.3";
tag_insight = "This update of freetype2 fixes multiple security flaws that
  could allow attackers to cause a denial of service or to
  execute arbitrary code via specially crafted fonts
  (CVE-2011-3256, CVE-2011-3439).";
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
  script_xref(name : "URL" , value : "http://195.135.221.135/opensuse-security-announce/2012-01/msg00036.html");
  script_id(850286);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-02 23:24:57 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-3256", "CVE-2011-3439");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "openSUSE-SU", value: "2012:0047_1");
  script_name("SuSE Update for freetype2 openSUSE-SU-2012:0047-1 (freetype2)");

  script_description(desc);
  script_summary("Check for the Version of freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.4.4~7.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.4.4~7.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.4.4~7.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.4.4~7.10.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.3.12~7.8.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.3.12~7.8.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.3.12~7.8.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.3.12~7.8.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
