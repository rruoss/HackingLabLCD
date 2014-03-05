###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for exim CESA-2011:0153 centos4 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  Cambridge for use on UNIX systems connected to the Internet.

  A privilege escalation flaw was discovered in Exim. If an attacker were
  able to gain access to the &quot;exim&quot; user, they could cause Exim to execute
  arbitrary commands as the root user. (CVE-2010-4345)
  
  This update adds a new configuration file, &quot;/etc/exim/trusted-configs&quot;. To
  prevent Exim from running arbitrary commands as root, Exim will now drop
  privileges when run with a configuration file not listed as trusted. This
  could break backwards compatibility with some Exim configurations, as the
  trusted-configs file only trusts &quot;/etc/exim/exim.conf&quot; and
  &quot;/etc/exim/exim4.conf&quot; by default. If you are using a configuration file
  not listed in the new trusted-configs file, you will need to add it
  manually.
  
  Additionally, Exim will no longer allow a user to execute exim as root with
  the -D command line option to override macro definitions. All macro
  definitions that require root permissions must now reside in a trusted
  configuration file.
  
  Users of Exim are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing this
  update, the exim daemon will be restarted automatically.";

tag_affected = "exim on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-January/017244.html");
  script_id(881419);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:50:06 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4345");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2011:0153");
  script_name("CentOS Update for exim CESA-2011:0153 centos4 x86_64");

  script_description(desc);
  script_summary("Check for the Version of exim");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"exim", rpm:"exim~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-doc", rpm:"exim-doc~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-mon", rpm:"exim-mon~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exim-sa", rpm:"exim-sa~4.43~1.RHEL4.5.el4_8.3", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}