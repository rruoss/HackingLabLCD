###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for tar FEDORA-2010-4306
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
tag_insight = "The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive. Tar
  can also be used to add supplemental files to an archive and to update
  or list files in the archive. Tar includes multivolume support,
  automatic archive compression/decompression, the ability to perform
  remote archives, and the ability to perform incremental and full
  backups.

  If you want to use tar for remote backups, you also need to install
  the rmt package.";

tag_affected = "tar on Fedora 11";
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
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-March/038149.html");
  script_id(861804);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-31 14:20:46 +0200 (Wed, 31 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2010-4306");
  script_cve_id("CVE-2010-0624");
  script_name("Fedora Update for tar FEDORA-2010-4306");

  script_description(desc);
  script_summary("Check for the Version of tar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"tar", rpm:"tar~1.22~5.fc11", rls:"FC11")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}