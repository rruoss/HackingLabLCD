###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for exim RHSA-2010:0970-01
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
tag_insight = "Exim is a mail transport agent (MTA) developed at the University of
  Cambridge for use on Unix systems connected to the Internet.

  A buffer overflow flaw was discovered in Exim's internal
  string_vformat() function. A remote attacker could use this flaw to
  execute arbitrary code on the mail server running Exim. (CVE-2010-4344)
  
  Note: successful exploitation would allow a remote attacker to execute
  arbitrary code as root on a Red Hat Enterprise Linux 4 or 5 system that
  is running the Exim mail server. An exploit for this issue is known to
  exist.
  
  For additional information regarding this flaw, along with mitigation
  advice, please see the Knowledge Base article linked to in the
  References section of this advisory.
  
  Users of Exim are advised to update to these erratum packages which
  contain a backported patch to correct this issue. After installing this
  update, the Exim daemon will be restarted automatically.";

tag_affected = "exim on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-December/msg00023.html");
  script_id(870369);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-28 07:11:56 +0100 (Tue, 28 Dec 2010)");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2010:0970-01");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4344");
  script_name("RedHat Update for exim RHSA-2010:0970-01");

  script_description(desc);
  script_summary("Check for the Version of exim");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.63~5.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-debuginfo", rpm:"exim-debuginfo~4.63~5.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.63~5.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.63~5.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.43~1.RHEL4.5.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-debuginfo", rpm:"exim-debuginfo~4.43~1.RHEL4.5.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-doc", rpm:"exim-doc~4.43~1.RHEL4.5.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.43~1.RHEL4.5.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.43~1.RHEL4.5.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
