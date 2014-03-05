###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for openwsman SUSE-SA:2008:041
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
tag_impact = "remote code execution";
tag_affected = "openwsman on openSUSE 10.3, openSUSE 11.0";
tag_insight = "The openwsman project provides an implementation of the Web Service
  Management specification.
  The SuSE Security-Team has found two critical issues in the code:
  - two remote buffer overflows while decoding the HTTP basic authentication
  header CVE-2008-2234
  - a possible SSL session replay attack affecting the client (depending on
  the configuration) CVE-2008-2233
  Both issues were fixed.";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2008_41_openwsman.html");
  script_id(850013);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2008-041");
  script_cve_id("CVE-2008-2233", "CVE-2008-2234", "CVE-2008-3337", "CVE-2008-1447", "CVE-2007-6389", "CVE-2008-2079", "CVE-2006-7232", "CVE-2008-1801", "CVE-2008-1802", "CVE-2008-1803");
  script_name( "SuSE Update for openwsman SUSE-SA:2008:041");

  script_description(desc);
  script_summary("Check for the Version of openwsman");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"openwsman", rpm:"openwsman~1.2.0~14.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-client", rpm:"openwsman-client~1.2.0~14.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-devel", rpm:"openwsman-devel~1.2.0~14.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-server", rpm:"openwsman-server~1.2.0~14.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"openwsman-debuginfo", rpm:"openwsman-debuginfo~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-debugsource", rpm:"openwsman-debugsource~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwsman-devel", rpm:"libwsman-devel~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwsman1", rpm:"libwsman1~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-client", rpm:"openwsman-client~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-python", rpm:"openwsman-python~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-ruby", rpm:"openwsman-ruby~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openwsman-server", rpm:"openwsman-server~2.0.0~3.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}