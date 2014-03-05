###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2010:0824-01
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
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  It was found that the MySQL PolyFromWKB() function did not sanity check
  Well-Known Binary (WKB) data. A remote, authenticated attacker could use
  specially-crafted WKB data to crash mysqld. This issue only caused a
  temporary denial of service, as mysqld was automatically restarted after
  the crash. (CVE-2010-3840)
  
  A flaw was found in the way MySQL processed certain alternating READ
  requests provided by HANDLER statements. A remote, authenticated attacker
  could use this flaw to provide such requests, causing mysqld to crash. This
  issue only caused a temporary denial of service, as mysqld was
  automatically restarted after the crash. (CVE-2010-3681)
  
  A directory traversal flaw was found in the way MySQL handled the
  parameters of the MySQL COM_FIELD_LIST network protocol command. A remote,
  authenticated attacker could use this flaw to obtain descriptions of the
  fields of an arbitrary table using a request with a specially-crafted
  table name. (CVE-2010-1848)
  
  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.";

tag_affected = "mysql on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-November/msg00002.html");
  script_id(870357);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2010:0824-01");
  script_cve_id("CVE-2010-1848", "CVE-2010-3681", "CVE-2010-3840");
  script_name("RedHat Update for mysql RHSA-2010:0824-01");

  script_description(desc);
  script_summary("Check for the Version of mysql");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~4.1.22~2.el4_8.4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~4.1.22~2.el4_8.4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~4.1.22~2.el4_8.4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~4.1.22~2.el4_8.4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~4.1.22~2.el4_8.4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
