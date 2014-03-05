###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zeroinstall-injector FEDORA-2013-12396
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
tag_insight = "The Zero Install Injector makes it easy for users to install software
  without needing root privileges. It takes the URL of a program and
  runs it (downloading it first if necessary). Any dependencies of the
  program are fetched in the same way. The user controls which version
  of the program and its dependencies to use.

  Zero Install is a decentralized installation system (there is no
  central repository; all packages are identified by URLs),
  loosely-coupled (if different programs require different versions of a
  library then both versions are installed in parallel, without
  conflicts), and has an emphasis on security (all package descriptions
  are GPG-signed, and contain cryptographic hashes of the contents of
  each version). Each version of each program is stored in its own
  sub-directory within the Zero Install cache (nothing is installed to
  directories outside of the cache, such as /usr/bin) and no code from
  the package is run during install or uninstall. The system can
  automatically check for updates when software is run.";


tag_affected = "zeroinstall-injector on Fedora 18";
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
  script_id(866066);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-16 10:15:10 +0530 (Tue, 16 Jul 2013)");
  script_cve_id("CVE-2013-2099", "CVE-2013-2098");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Fedora Update for zeroinstall-injector FEDORA-2013-12396");

  script_description(desc);
  script_xref(name: "FEDORA", value: "2013-12396");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-July/111599.html");
  script_summary("Check for the Version of zeroinstall-injector");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"zeroinstall-injector", rpm:"zeroinstall-injector~2.3~1.fc18", rls:"FC18")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
