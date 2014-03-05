###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for finch CESA-2010:0788 centos4 i386
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
tag_insight = "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  Multiple NULL pointer dereference flaws were found in the way Pidgin
  handled Base64 decoding. A remote attacker could use these flaws to crash
  Pidgin if the target Pidgin user was using the Yahoo! Messenger Protocol,
  MSN, MySpace, or Extensible Messaging and Presence Protocol (XMPP) protocol
  plug-ins, or using the Microsoft NT LAN Manager (NTLM) protocol for
  authentication. (CVE-2010-3711)

  A NULL pointer dereference flaw was found in the way the Pidgin MSN
  protocol plug-in processed custom emoticon messages. A remote attacker
  could use this flaw to crash Pidgin by sending specially-crafted emoticon
  messages during mutual communication. (CVE-2010-1624)

  Red Hat would like to thank the Pidgin project for reporting these issues.
  Upstream acknowledges Daniel Atallah as the original reporter of
  CVE-2010-3711, and Pierre Nogus of Meta Security as the original reporter
  of CVE-2010-1624.

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "finch on CentOS 4";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-October/017117.html");
  script_id(880447);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-04 12:09:38 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "CESA", value: "2010:0788");
  script_cve_id("CVE-2010-1624", "CVE-2010-3711");
  script_name("CentOS Update for finch CESA-2010:0788 centos4 i386");

  script_description(desc);
  script_summary("Check for the Version of finch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.6~5.el4", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
