###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for quagga RHSA-2012:1259-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Quagga is a TCP/IP based routing software suite. The Quagga bgpd daemon
  implements the BGP (Border Gateway Protocol) routing protocol. The Quagga
  ospfd and ospf6d daemons implement the OSPF (Open Shortest Path First)
  routing protocol.

  A heap-based buffer overflow flaw was found in the way the bgpd daemon
  processed malformed Extended Communities path attributes. An attacker could
  send a specially-crafted BGP message, causing bgpd on a target system to
  crash or, possibly, execute arbitrary code with the privileges of the user
  running bgpd. The UPDATE message would have to arrive from an explicitly
  configured BGP peer, but could have originated elsewhere in the BGP
  network. (CVE-2011-3327)

  A stack-based buffer overflow flaw was found in the way the ospf6d daemon
  processed malformed Link State Update packets. An OSPF router could use
  this flaw to crash ospf6d on an adjacent router. (CVE-2011-3323)

  A flaw was found in the way the ospf6d daemon processed malformed link
  state advertisements. An OSPF neighbor could use this flaw to crash
  ospf6d on a target system. (CVE-2011-3324)

  Description truncated, for more information please check the Reference URL";

tag_affected = "quagga on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-September/msg00015.html");
  script_id(870828);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:41:23 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326",
                "CVE-2011-3327", "CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255",
                "CVE-2012-1820");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2012:1259-01");
  script_name("RedHat Update for quagga RHSA-2012:1259-01");

  script_description(desc);
  script_summary("Check for the Version of quagga");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.15~7.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~0.99.15~7.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}