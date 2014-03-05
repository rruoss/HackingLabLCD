###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for avahi CESA-2011:0436 centos5 i386
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
tag_insight = "Avahi is an implementation of the DNS Service Discovery and Multicast DNS
  specifications for Zero Configuration Networking. It facilitates service
  discovery on a local network. Avahi and Avahi-aware applications allow you
  to plug your computer into a network and, with no configuration, view other
  people to chat with, view printers to print to, and find shared files on
  other computers.

  A flaw was found in the way the Avahi daemon (avahi-daemon) processed
  Multicast DNS (mDNS) packets with an empty payload. An attacker on the
  local network could use this flaw to cause avahi-daemon on a target system
  to enter an infinite loop via an empty mDNS UDP packet. (CVE-2011-1002)
  
  All users are advised to upgrade to these updated packages, which contain
  a backported patch to correct this issue. After installing the update,
  avahi-daemon will be restarted automatically.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "avahi on CentOS 5";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017293.html");
  script_id(880557);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "CESA", value: "2011:0436");
  script_cve_id("CVE-2011-1002", "CVE-2010-2244");
  script_name("CentOS Update for avahi CESA-2011:0436 centos5 i386");

  script_description(desc);
  script_summary("Check for the Version of avahi");
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

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-howl", rpm:"avahi-compat-howl~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd", rpm:"avahi-compat-libdns_sd~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd-devel", rpm:"avahi-compat-libdns_sd-devel~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-devel", rpm:"avahi-devel~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-glib", rpm:"avahi-glib~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-glib-devel", rpm:"avahi-glib-devel~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-qt3", rpm:"avahi-qt3~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-qt3-devel", rpm:"avahi-qt3-devel~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-tools", rpm:"avahi-tools~0.6.16~10.el5_6", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}