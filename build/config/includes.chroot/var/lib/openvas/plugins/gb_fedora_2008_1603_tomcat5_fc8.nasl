###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for tomcat5 FEDORA-2008-1603
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
tag_insight = "Tomcat is the servlet container that is used in the official Reference
  Implementation for the Java Servlet and JavaServer Pages technologies.
  The Java Servlet and JavaServer Pages specifications are developed by
  Sun under the Java Community Process.

  Tomcat is developed in an open and participatory environment and
  released under the Apache Software License. Tomcat is intended to be
  a collaboration of the best-of-breed developers from around the world.
  We invite you to participate in this open development project. To
  learn more about getting involved, click here.";

tag_affected = "tomcat5 on Fedora 8";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-February/msg00460.html");
  script_id(860345);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-16 14:16:57 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2008-1603");
  script_cve_id("CVE-2007-5342", "CVE-2007-5333", "CVE-2007-5461", "CVE-2007-6286", "CVE-2007-1355", "CVE-2007-3386", "CVE-2007-3385", "CVE-2007-3382", "CVE-2007-2450", "CVE-2007-2449", "CVE-2007-1358", "CVE-2008-0002");
  script_name( "Fedora Update for tomcat5 FEDORA-2008-1603");

  script_description(desc);
  script_summary("Check for the Version of tomcat5");
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.26~1jpp.2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
