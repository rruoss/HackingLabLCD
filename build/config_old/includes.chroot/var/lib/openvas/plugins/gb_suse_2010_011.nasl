###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for postfix SUSE-SA:2010:011
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The value of SMTPD_LISTEN_REMOTE accidentally defaulted to 'yes'. The postfix
  smtp daemon therefore was reachable over the network by default.
  This update resets the value to 'no' in /etc/sysconfig/mail. If you
  intentionally want postfix to listen for remote connections you need to
  manually set it to 'yes' again.

  This update also fixes a problem where the relay database was not created and
  postfix refused to start.";

tag_impact = "remote denial of service";
tag_affected = "postfix on openSUSE 11.2";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2010_11_postfix.html");
  script_id(850126);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-19 13:38:15 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2010-011");
  script_cve_id("CVE-2010-0230");
  script_name("SuSE Update for postfix SUSE-SA:2010:011");

  script_description(desc);
  script_summary("Check for the Version of postfix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~2.6.1~2.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
