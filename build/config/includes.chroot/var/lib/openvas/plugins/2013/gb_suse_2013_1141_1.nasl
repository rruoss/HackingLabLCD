###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2013:1141-1 (MozillaThunderbird)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(850495);
  script_version("$Revision: 74 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 13:29:03 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:06:01 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693",
                "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2013:1141-1 (MozillaThunderbird)");

  tag_insight = "
  MozillaThunderbird was updated to Thunderbird 17.0.7
  (bnc#825935)

  Security issues fixed:
  * MFSA 2013-49/CVE-2013-1682 Miscellaneous memory safety
  hazards
  * MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
  Memory corruption found using Address Sanitizer
  * MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
  Privileged content access and execution via XBL
  * MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
  unmapped memory through onreadystatechange event
  * MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the
  body of XHR HEAD requests leads to CSRF attacks
  * MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
  lead to information disclosure
  * MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
  has inconsistent behavior
  * MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers
  can be bypassed to run user defined methods in a
  privileged contex";

  tag_affected = "MozillaThunderbird on openSUSE 12.2";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }

  script_description(desc);
  script_xref(name: "openSUSE-SU", value: "2013:1141_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2013-07/msg00004.html");
  script_summary("Check for the Version of MozillaThunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel-debuginfo", rpm:"MozillaThunderbird-devel-debuginfo~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.5.1+17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail-debuginfo", rpm:"enigmail-debuginfo~1.5.1+17.0.7~49.47.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
