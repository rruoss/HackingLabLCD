###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dbus RHSA-2011:1132-01
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
tag_insight = "D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  A denial of service flaw was found in the way the D-Bus library handled
  endianness conversion when receiving messages. A local user could use this
  flaw to send a specially-crafted message to dbus-daemon or to a service
  using the bus, such as Avahi or NetworkManager, possibly causing the
  daemon to exit or the service to disconnect from the bus. (CVE-2011-2200)
  
  All users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. For the update to take effect, all
  running instances of dbus-daemon and all running applications using the
  libdbus library must be restarted, or the system rebooted.";

tag_affected = "dbus on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-August/msg00004.html");
  script_id(870464);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2011:1132-01");
  script_cve_id("CVE-2011-2200");
  script_name("RedHat Update for dbus RHSA-2011:1132-01");

  script_description(desc);
  script_summary("Check for the Version of dbus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.1.2~16.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-debuginfo", rpm:"dbus-debuginfo~1.1.2~16.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-devel", rpm:"dbus-devel~1.1.2~16.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-libs", rpm:"dbus-libs~1.1.2~16.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.1.2~16.el5_7", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}