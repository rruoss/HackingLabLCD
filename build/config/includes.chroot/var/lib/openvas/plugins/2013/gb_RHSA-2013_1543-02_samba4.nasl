###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for samba4 RHSA-2013:1543-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(871076);
  script_version("$Revision: 74 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 13:29:03 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:03 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-4124");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("RedHat Update for samba4 RHSA-2013:1543-02");

  tag_insight = "Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

An integer overflow flaw was found in the way Samba handled an Extended
Attribute (EA) list provided by a client. A malicious client could send a
specially crafted EA list that triggered an overflow, causing the server to
loop and reprocess the list using an excessive amount of memory.
(CVE-2013-4124)

Note: This issue did not affect the default configuration of the
Samba server.

This update fixes the following bugs:

* When Samba was installed in the build root directory, the RPM target
might not have existed. Consequently, the find-debuginfo.sh script did not
create symbolic links for the libwbclient.so.debug module associated with
the target. With this update, the paths to the symbolic links are relative
so that the symbolic links are now created correctly. (BZ#882338)

* Previously, the samba4 packages were missing a dependency for the
libreplace.so module which could lead to installation failures. With this
update, the missing dependency has been added to the dependency list of the
samba4 packages and installation now proceeds as expected. (BZ#911264)

All samba4 users are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues.
";

  tag_affected = "samba4 on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "RHSA", value: "2013:1543-02");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-November/msg00020.html");
  script_summary("Check for the Version of samba4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"samba4", rpm:"samba4~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-client", rpm:"samba4-client~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-common", rpm:"samba4-common~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-dc", rpm:"samba4-dc~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-dc-libs", rpm:"samba4-dc-libs~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-debuginfo", rpm:"samba4-debuginfo~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-devel", rpm:"samba4-devel~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-libs", rpm:"samba4-libs~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-pidl", rpm:"samba4-pidl~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-python", rpm:"samba4-python~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-swat", rpm:"samba4-swat~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-test", rpm:"samba4-test~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind", rpm:"samba4-winbind~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind-clients", rpm:"samba4-winbind-clients~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba4-winbind-krb5-locator", rpm:"samba4-winbind-krb5-locator~4.0.0~58.el6.rc4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}