###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for libsoup MDVSA-2012:036 (libsoup)
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
tag_insight = "A vulnerability has been found and corrected in libsoup:

  Directory traversal vulnerability in soup-uri.c in SoupServer in
  libsoup before 2.35.4 allows remote attackers to read arbitrary files
  via a %2e%2e (encoded dot dot) in a URI (CVE-2011-2524).

  The updated packages have been patched to correct this issue.";

tag_affected = "libsoup on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1";
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
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:036");
  script_id(831650);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-08-03 09:58:37 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2011-2524");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2012:036");
  script_name("Mandriva Update for libsoup MDVSA-2012:036 (libsoup)");

  script_description(desc);
  script_summary("Check for the Version of libsoup");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4_1~2.34.2~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4~devel~2.34.2~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4_1~2.34.2~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4~devel~2.34.2~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4_1~2.24.0.1~1.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4~devel~2.24.0.1~1.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4_1~2.24.0.1~1.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4~devel~2.24.0.1~1.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4_1~2.30.2~1.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.4~devel~2.30.2~1.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4_1~2.30.2~1.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64soup", rpm:"lib64soup~2.4~devel~2.30.2~1.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}