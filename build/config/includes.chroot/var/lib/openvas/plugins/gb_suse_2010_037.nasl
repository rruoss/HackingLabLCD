###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for acroread SUSE-SA:2010:037
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
tag_insight = "Specially crafted PDF documents could crash acroread or  lead to
  execution of arbitrary code CVE-2010-2862.

  This update also incorporate the Adobe Flash Player update APSB10-16
  for the bundled flash player parts CVE-2010-2188,
  CVE-2010-2216.

  Please see Adobe's site for more information:
  http://www.adobe.com/support/security/bulletins/apsb10-17.html";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "remote code execution";
tag_affected = "acroread on openSUSE 11.1, openSUSE 11.2";

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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2010_37_acroread.html");
  script_id(850141);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 14:21:00 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2010-037");
  script_cve_id("CVE-2010-0209", "CVE-2010-1240", "CVE-2010-2188", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215", "CVE-2010-2216", "CVE-2010-2862");
  script_name("SuSE Update for acroread SUSE-SA:2010:037");

  script_description(desc);
  script_summary("Check for the Version of acroread");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "openSUSE11.1")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.3.4~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~9.3.4~0.3.1", rls:"openSUSE11.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
