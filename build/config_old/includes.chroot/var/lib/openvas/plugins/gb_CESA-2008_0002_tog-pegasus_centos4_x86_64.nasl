###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for tog-pegasus CESA-2008:0002 centos4 x86_64
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
tag_insight = "The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
  Management (WBEM) services. WBEM is a platform and resource independent
  DMTF standard that defines a common information model, and communication
  protocol for monitoring and controlling resources.

  During a security audit, a stack buffer overflow flaw was found in the PAM
  authentication code in the OpenPegasus CIM management server. An
  unauthenticated remote user could trigger this flaw and potentially execute
  arbitrary code with root privileges. (CVE-2008-0003)
  
  Note that the tog-pegasus packages are not installed by default on Red Hat
  Enterprise Linux. The Red Hat Security Response Team believes that it would
  be hard to remotely exploit this issue to execute arbitrary code, due to
  the default SELinux targeted policy on Red Hat Enterprise Linux 4 and 5,
  and the SELinux memory protection tests enabled by default on Red Hat
  Enterprise Linux 5.
  
  Users of tog-pegasus should upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing the
  updated packages the tog-pegasus service should be restarted.";

tag_affected = "tog-pegasus on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014600.html");
  script_id(880110);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2008:0002");
  script_cve_id("CVE-2008-0003");
  script_name( "CentOS Update for tog-pegasus CESA-2008:0002 centos4 x86_64");

  script_description(desc);
  script_summary("Check for the Version of tog-pegasus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.5.1~5.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.5.1~5.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tog-pegasus-test", rpm:"tog-pegasus-test~2.5.1~5.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
