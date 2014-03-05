###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postfix CESA-2011:0843 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  A heap-based buffer over-read flaw was found in the way Postfix performed
  SASL handlers management for SMTP sessions, when Cyrus SASL authentication
  was enabled. A remote attacker could use this flaw to cause the Postfix
  smtpd server to crash via a specially-crafted SASL authentication request.
  The smtpd process was automatically restarted by the postfix master process
  after the time configured with service_throttle_time elapsed.
  (CVE-2011-1720)
  
  Note: Cyrus SASL authentication for Postfix is not enabled by default.
  
  Red Hat would like to thank the CERT/CC for reporting this issue. Upstream
  acknowledges Thomas Jarosch of Intra2net AG as the original reporter.
  
  Users of Postfix are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the postfix service will be restarted automatically.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "postfix on CentOS 4";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-June/017605.html");
  script_id(880488);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2011:0843");
  script_cve_id("CVE-2011-1720");
  script_name("CentOS Update for postfix CESA-2011:0843 centos4 i386");

  script_description(desc);
  script_summary("Check for the Version of postfix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.10~1.5.el4", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-pflogsumm", rpm:"postfix-pflogsumm~2.2.10~1.5.el4", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
