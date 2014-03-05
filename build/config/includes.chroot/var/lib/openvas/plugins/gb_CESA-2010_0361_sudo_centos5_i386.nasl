###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sudo CESA-2010:0361 centos5 i386
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
tag_insight = "The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  The RHBA-2010:0212 sudo update released as part of Red Hat Enterprise Linux
  5.5 added the ability to change the value of the ignore_dot option in the
  &quot;/etc/sudoers&quot; configuration file. This ability introduced a regression in
  the upstream fix for CVE-2010-0426. In configurations where the ignore_dot
  option was set to off (the default is on for the Red Hat Enterprise Linux 5
  sudo package), a local user authorized to use the sudoedit pseudo-command
  could possibly run arbitrary commands with the privileges of the users
  sudoedit was authorized to run as. (CVE-2010-1163)
  
  Red Hat would like to thank Todd C. Miller, the upstream sudo maintainer,
  for responsibly reporting this issue. Upstream acknowledges Valerio
  Costamagna as the original reporter.
  
  Users of sudo should upgrade to this updated package, which contains a
  backported patch to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "sudo on CentOS 5";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-May/016659.html");
  script_id(880570);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2010:0361");
  script_cve_id("CVE-2010-1163", "CVE-2010-0426");
  script_name("CentOS Update for sudo CESA-2010:0361 centos5 i386");

  script_description(desc);
  script_summary("Check for the Version of sudo");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~6.el5_5", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
