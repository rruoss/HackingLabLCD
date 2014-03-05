###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for acroread SUSE-SA:2007:011
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
tag_insight = "The Adobe Acrobat Reader has been updated to version 7.0.9.

  This update also includes following security fixes:

  CVE-2006-5857: A memory corruption problem was fixed in Adobe Acrobat
  Reader can potentially lead to code execution.

  CVE-2007-0044: Universal Cross Site Request Forgery (CSRF) problems
  were fixed in the Acrobat Reader plugin which could be
  exploited by remote attackers to conduct CSRF attacks
  using any site that is providing PDFs.

  CVE-2007-0045: Cross site scripting problems in the Acrobat Reader
  plugin were fixed, which could be exploited by remote
  attackers to conduct XSS attacks against any site that
  is providing PDFs.

  CVE-2007-0046: A double free problem in the Acrobat Reader plugin was fixed
  which could be used by remote attackers to potentially execute
  arbitrary code.
  Note that all platforms using Adobe Reader currently have
  counter measures against such attack where it will just
  cause a controlled abort().

  CVE-2007-0048 affect only Microsoft Windows and
  Internet Explorer.

  Please note that the Acrobat Reader on SUSE Linux Enterprise Server
  9 is affected too, but can not be updated currently due to GTK+
  2.4 requirements.  We are trying to find a solution.

  Acrobat Reader on SUSE Linux Enterprise Server 8 and SUSE Linux
  Desktop 1 is no longer supported and should be deinstalled.";

tag_impact = "remote code execution";
tag_affected = "acroread on SUSE LINUX 10.1, openSUSE 10.2, Novell Linux Desktop 9, SUSE SLED 10";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_11_acroread.html");
  script_id(850062);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2007-011");
  script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0048");
  script_name( "SuSE Update for acroread SUSE-SA:2007:011");

  script_description(desc);
  script_summary("Check for the Version of acroread");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~7.0.9~1.2", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~7.0.9~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~7.0.9~2.1", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~7.0.9~1.2", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
