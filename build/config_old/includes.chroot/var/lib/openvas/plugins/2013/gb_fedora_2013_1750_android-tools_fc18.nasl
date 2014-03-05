###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for android-tools FEDORA-2013-1750
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
tag_insight = "The Android Debug Bridge (ADB) is used to:

  - keep track of all Android devices and emulators instances
    connected to or running on a given host developer machine

  - implement various control commands (e.g. &quot;adb shell&quot;, &quot;adb pull&quot;, etc.)
    for the benefit of clients (command-line users, or helper programs like
    DDMS). These commands are what is called a 'service' in ADB.

  Fastboot is used to manipulate the flash partitions of the Android phone.
  It can also boot the phone using a kernel image or root filesystem image
  which reside on the host machine rather than in the phone flash.
  In order to use it, it is important to understand the flash partition
  layout for the phone.
  The fastboot program works in conjunction with firmware on the phone
  to read and write the flash partitions. It needs the same USB device
  setup between the host and the target phone as adb.";


tag_affected = "android-tools on Fedora 18";
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
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098532.html");
  script_id(865332);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-11 10:10:23 +0530 (Mon, 11 Feb 2013)");
  script_cve_id("CVE-2012-5564");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2013-1750");
  script_name("Fedora Update for android-tools FEDORA-2013-1750");

  script_description(desc);
  script_summary("Check for the Version of android-tools");
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

  if ((res = isrpmvuln(pkg:"android-tools", rpm:"android-tools~20130123git98d0789~1.fc18", rls:"FC18")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
