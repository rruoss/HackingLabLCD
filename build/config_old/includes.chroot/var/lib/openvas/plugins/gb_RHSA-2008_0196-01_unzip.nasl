###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for unzip RHSA-2008:0196-01
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
tag_insight = "The unzip utility is used to list, test, or extract files from a zip
  archive.

  An invalid pointer flaw was found in unzip. If a user ran unzip on a
  specially crafted file, an attacker could execute arbitrary code with that
  user's privileges. (CVE-2008-0888)
  
  Red Hat would like to thank Tavis Ormandy of the Google Security Team for
  reporting this issue.
  
  All unzip users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.";

tag_affected = "unzip on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1,
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-March/msg00013.html");
  script_id(870037);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2008:0196-01");
  script_cve_id("CVE-2008-0888");
  script_name( "RedHat Update for unzip RHSA-2008:0196-01");

  script_description(desc);
  script_summary("Check for the Version of unzip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~5.50~31.EL2.1", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~5.50~36.EL3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-debuginfo", rpm:"unzip-debuginfo~5.50~36.EL3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
