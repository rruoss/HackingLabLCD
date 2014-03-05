###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for perl-Archive-Tar CESA-2010:0505 centos5 i386
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
tag_insight = "The Archive::Tar module provides a mechanism for Perl scripts to manipulate
  tar archive files.

  Multiple directory traversal flaws were discovered in the Archive::Tar
  module. A specially-crafted tar file could cause a Perl script, using the
  Archive::Tar module to extract the archive, to overwrite an arbitrary file
  writable by the user running the script. (CVE-2007-4829)
  
  This package upgrades the Archive::Tar module to version 1.39_01. Refer to
  the Archive::Tar module's changes file, linked to in the References, for a
  full list of changes.
  
  Users of perl-Archive-Tar are advised to upgrade to this updated package,
  which corrects these issues. All applications using the Archive::Tar module
  must be restarted for this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "perl-Archive-Tar on CentOS 5";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-July/016750.html");
  script_id(880608);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2010:0505");
  script_cve_id("CVE-2007-4829");
  script_name("CentOS Update for perl-Archive-Tar CESA-2010:0505 centos5 i386");

  script_description(desc);
  script_summary("Check for the Version of perl-Archive-Tar");
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

  if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.39.1~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
