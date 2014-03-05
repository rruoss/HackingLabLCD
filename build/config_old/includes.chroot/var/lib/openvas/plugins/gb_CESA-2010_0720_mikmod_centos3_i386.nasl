###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mikmod CESA-2010:0720 centos3 i386
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
tag_insight = "MikMod is a MOD music file player for Linux, UNIX, and similar operating
  systems. It supports various file formats including MOD, STM, S3M, MTM, XM,
  ULT, and IT.

  Multiple input validation flaws, resulting in buffer overflows, were
  discovered in MikMod. Specially-crafted music files in various formats
  could, when played, cause an application using the MikMod library to crash
  or, potentially, execute arbitrary code. (CVE-2009-3995, CVE-2009-3996,
  CVE-2007-6720)

  All MikMod users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  the MikMod library must be restarted for this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "mikmod on CentOS 3";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-September/017024.html");
  script_id(880431);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-01 16:10:21 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2010:0720");
  script_cve_id("CVE-2007-6720", "CVE-2009-3995", "CVE-2009-3996");
  script_name("CentOS Update for mikmod CESA-2010:0720 centos3 i386");

  script_description(desc);
  script_summary("Check for the Version of mikmod");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"mikmod", rpm:"mikmod~3.1.6~23.el3", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mikmod-devel", rpm:"mikmod-devel~3.1.6~23.el3", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
