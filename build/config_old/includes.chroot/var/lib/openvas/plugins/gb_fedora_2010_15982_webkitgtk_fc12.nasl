###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for webkitgtk FEDORA-2010-15982
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
tag_affected = "webkitgtk on Fedora 12";
tag_insight = "WebKitGTK+ is the port of the portable web rendering engine WebKit to the
  GTK+ platform.";
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
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049544.html");
  script_id(862461);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2010-15982");
  script_cve_id("CVE-2010-1407", "CVE-2010-1405", "CVE-2010-1664", "CVE-2010-1421", "CVE-2010-1807", "CVE-2010-1760", "CVE-2010-1422", "CVE-2010-1665", "CVE-2010-1771", "CVE-2010-2648", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1788", "CVE-2010-1762", "CVE-2010-1386", "CVE-2010-2264", "CVE-2010-1761", "CVE-2010-3259", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1770", "CVE-2010-1773", "CVE-2010-3257", "CVE-2010-1774", "CVE-2010-1759", "CVE-2010-1767", "CVE-2010-3113", "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-1758", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-1812", "CVE-2010-1793", "CVE-2010-1792", "CVE-2010-1790", "CVE-2010-1772", "CVE-2010-1392");
  script_name("Fedora Update for webkitgtk FEDORA-2010-15982");

  script_description(desc);
  script_summary("Check for the Version of webkitgtk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~1.2.5~1.fc12", rls:"FC12")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}