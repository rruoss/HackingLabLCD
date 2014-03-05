###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss_db RHSA-2010:0347-01
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
tag_insight = "The nss_db packages provide a set of C library extensions which allow
  Berkeley Database (Berkeley DB) databases to be used as a primary source of
  aliases, ethers, groups, hosts, networks, protocols, users, RPCs, services,
  and shadow passwords. These databases are used instead of or in addition to
  the flat files used by these tools by default.

  It was discovered that nss_db did not specify a path to the directory to be
  used as the database environment for the Berkeley Database library, causing
  it to use the current working directory as the default. This could possibly
  allow a local attacker to obtain sensitive information. (CVE-2010-0826)
  
  Users of nss_db are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.";

tag_affected = "nss_db on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-April/msg00005.html");
  script_id(870257);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 17:02:11 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_xref(name: "RHSA", value: "2010:0347-01");
  script_cve_id("CVE-2010-0826");
  script_name("RedHat Update for nss_db RHSA-2010:0347-01");

  script_description(desc);
  script_summary("Check for the Version of nss_db");
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

  if ((res = isrpmvuln(pkg:"nss_db", rpm:"nss_db~2.2~35.4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_db-debuginfo", rpm:"nss_db-debuginfo~2.2~35.4.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_note(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
