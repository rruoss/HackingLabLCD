###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for quagga FEDORA-2007-2196
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
tag_insight = "Quagga is a free software that manages TCP/IP based routing
  protocol. It takes multi-server and multi-thread approach to resolve
  the current complexity of the Internet.

  Quagga supports BGP4, BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng.
  
  Quagga is intended to be used as a Route Server and a Route Reflector. It is
  not a toolkit, it provides full routing power under a new architecture.
  Quagga by design has a process for each protocol.
  
  Quagga is a fork of GNU Zebra.";

tag_affected = "quagga on Fedora 7";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-September/msg00304.html");
  script_id(861045);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2007-2196");
  script_cve_id("CVE-2007-4826", "CVE-2007-1995");
  script_name( "Fedora Update for quagga FEDORA-2007-2196");

  script_description(desc);
  script_summary("Check for the Version of quagga");
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

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.9~1.fc7", rls:"FC7")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
