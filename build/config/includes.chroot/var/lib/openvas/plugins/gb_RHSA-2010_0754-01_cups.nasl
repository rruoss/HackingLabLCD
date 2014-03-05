###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cups RHSA-2010:0754-01
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
tag_insight = "The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems. The CUPS &quot;pdftops&quot; filter converts Portable
  Document Format (PDF) files to PostScript.

  An uninitialized pointer use flaw was discovered in the CUPS &quot;pdftops&quot;
  filter. An attacker could create a malicious PDF file that, when printed,
  would cause &quot;pdftops&quot; to crash or, potentially, execute arbitrary code as
  the &quot;lp&quot; user. (CVE-2010-3702)
  
  Users of cups are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing this
  update, the cupsd daemon will be restarted automatically.";

tag_affected = "cups on Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-October/msg00009.html");
  script_id(870337);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2010:0754-01");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3702");
  script_name("RedHat Update for cups RHSA-2010:0754-01");

  script_description(desc);
  script_summary("Check for the Version of cups");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.70", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.1.17~13.3.70", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.70", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.70", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
