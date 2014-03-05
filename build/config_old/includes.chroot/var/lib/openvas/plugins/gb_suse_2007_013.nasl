###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for xine-ui,xine-lib,xine-extra,xine-devel SUSE-SA:2007:013
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
tag_affected = "xine-ui,xine-lib,xine-extra,xine-devel on SUSE LINUX 10.1, openSUSE 10.2, SUSE SLED 10";
tag_insight = "This update fixes several format string bugs that can be exploited remotely
  with user-assistance to execute arbitrary code.
  Since SUSE Linux version 10.1 format string bugs are not exploitable
  anymore. CVE-2007-0017";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_13_xine.html");
  script_id(850063);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2007-013");
  script_cve_id("CVE-2007-0017");
  script_name( "SuSE Update for xine-ui,xine-lib,xine-extra,xine-devel SUSE-SA:2007:013");

  script_description(desc);
  script_summary("Check for the Version of xine-ui,xine-lib,xine-extra,xine-devel");
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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"xine-extra", rpm:"xine-extra~1.1.1~24.17", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.1~24.17", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib-32bit", rpm:"xine-lib-32bit~1.1.1~24.17", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-ui", rpm:"xine-ui~0.99.4~32.14", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"xine-devel", rpm:"xine-devel~1.1.2~40.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-extra", rpm:"xine-extra~1.1.2~40.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.2~40.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-ui", rpm:"xine-ui~0.99.4~84.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib-32bit", rpm:"xine-lib-32bit~1.1.2~40.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-ui-32bit", rpm:"xine-ui-32bit~0.99.4~84.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"xine-extra", rpm:"xine-extra~1.1.1~24.17", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.1~24.17", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xine-ui", rpm:"xine-ui~0.99.4~32.14", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}