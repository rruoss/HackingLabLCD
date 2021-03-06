###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kdegraphics CESA-2009:1130 centos5 i386
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
tag_insight = "The kdegraphics packages contain applications for the K Desktop Environment
  (KDE). Scalable Vector Graphics (SVG) is an XML-based language to describe
  vector images. KSVG is a framework aimed at implementing the latest W3C SVG
  specifications.

  A use-after-free flaw was found in the KDE KSVG animation element
  implementation. A remote attacker could create a specially-crafted SVG
  image, which once opened by an unsuspecting user, could cause a denial of
  service (Konqueror crash) or, potentially, execute arbitrary code with the
  privileges of the user running Konqueror. (CVE-2009-1709)
  
  A NULL pointer dereference flaw was found in the KDE, KSVG SVGList
  interface implementation. A remote attacker could create a
  specially-crafted SVG image, which once opened by an unsuspecting user,
  would cause memory corruption, leading to a denial of service (Konqueror
  crash). (CVE-2009-0945)
  
  All users of kdegraphics should upgrade to these updated packages, which
  contain backported patches to correct these issues. The desktop must be
  restarted (log out, then log back in) for this update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "kdegraphics on CentOS 5";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-June/016009.html");
  script_id(880857);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2009:1130");
  script_cve_id("CVE-2009-0945", "CVE-2009-1709");
  script_name("CentOS Update for kdegraphics CESA-2009:1130 centos5 i386");

  script_description(desc);
  script_summary("Check for the Version of kdegraphics");
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

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.4~13.el5_3", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-devel", rpm:"kdegraphics-devel~3.5.4~13.el5_3", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
