###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for cups CESA-2013:0580 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  for Linux, UNIX, and similar operating systems.

  It was discovered that CUPS administrative users (members of the
  SystemGroups groups) who are permitted to perform CUPS configuration
  changes via the CUPS web interface could manipulate the CUPS configuration
  to gain unintended privileges. Such users could read or write arbitrary
  files with the privileges of the CUPS daemon, possibly allowing them to
  run arbitrary code with root privileges. (CVE-2012-5519)
  
  After installing this update, the ability to change certain CUPS
  configuration directives remotely will be disabled by default. The newly
  introduced ConfigurationChangeRestriction directive can be used to enable
  the changing of the restricted directives remotely. Refer to Red Hat
  Bugzilla bug 875898 for more details and the list of restricted directives.
  
  All users of cups are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the cupsd daemon will be restarted automatically.";


tag_affected = "cups on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019616.html");
  script_id(881674);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:02:13 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-5519");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2013:0580");
  script_name("CentOS Update for cups CESA-2013:0580 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of cups");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~50.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~50.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~50.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~50.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-php", rpm:"cups-php~1.4.2~50.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
