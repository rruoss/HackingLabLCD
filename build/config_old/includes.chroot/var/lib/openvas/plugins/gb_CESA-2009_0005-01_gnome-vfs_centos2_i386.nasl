###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gnome-vfs CESA-2009:0005-01 centos2 i386
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
tag_insight = "GNOME VFS is the GNOME virtual file system. It provides a modular
  architecture and ships with several modules that implement support for
  various local and remote file systems as well as numerous protocols,
  including HTTP, FTP, and others.

  A buffer overflow flaw was discovered in the GNOME virtual file system when
  handling data returned by CDDB servers. If a user connected to a malicious
  CDDB server, an attacker could use this flaw to execute arbitrary code on
  the victim's machine. (CVE-2005-0706)
  
  Users of gnome-vfs and gnome-vfs2 are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue. All
  running GNOME sessions must be restarted for the update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gnome-vfs on CentOS 2";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-February/015573.html");
  script_id(880939);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2009:0005-01");
  script_cve_id("CVE-2005-0706");
  script_name("CentOS Update for gnome-vfs CESA-2009:0005-01 centos2 i386");

  script_description(desc);
  script_summary("Check for the Version of gnome-vfs");
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

if(release == "CentOS2")
{

  if ((res = isrpmvuln(pkg:"gnome-vfs", rpm:"gnome-vfs~1.0.1~18.2", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfs-devel", rpm:"gnome-vfs-devel~1.0.1~18.2", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}