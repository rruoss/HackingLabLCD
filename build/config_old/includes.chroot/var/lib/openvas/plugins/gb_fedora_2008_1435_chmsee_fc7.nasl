###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for chmsee FEDORA-2008-1435
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
tag_insight = "A gtk2 chm document viewer.

  It uses chmlib to extract files. It uses gecko to display pages. It supports
  displaying multilingual pages due to gecko. It features bookmarks and tabs.
  The tabs could be used to jump inside the chm file conveniently. Its UI is
  clean and handy, also is well localized. It is actively developed and
  maintained. The author of chmsee is Jungle Ji and several other great people.
  
  Hint
  * Unlike other chm viewers, chmsee extracts files from chm file, and then read
  and display them. The extracted files could be found in $HOME/.chmsee/bookshelf
  directory. You can clean those files at any time and there is a special config
  option for that.
  * The bookmark is related to each file so not all bookmarks will be loaded,
  only current file's.
  * Try to remove $HOME/.chmsee if you encounter any problem after an upgrade.";

tag_affected = "chmsee on Fedora 7";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-February/msg00272.html");
  script_id(860588);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-16 14:16:57 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2008-1435");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0593", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0592", "CVE-2008-0414", "CVE-2008-0594");
  script_name( "Fedora Update for chmsee FEDORA-2008-1435");

  script_description(desc);
  script_summary("Check for the Version of chmsee");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"chmsee", rpm:"chmsee~1.0.0~1.28.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
