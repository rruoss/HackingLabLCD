###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for printerdrake MDKA-2007:122 (printerdrake)
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
tag_insight = "In Mandriva Linux 2007 Spring, printerdrake would not detect many
  network printers, due to defaulting to using a less comprehensive
  printer scan method than previous releases did. (bug 30090)

  When changing the protocol for a configured network printer,
  printerdrake released with Mandriva Linux 2007 Spring would not update
  the associated protocol port number, leaving it in a non-working
  state. Also, general reconfiguration of network printers would fail,
  due to the use of an incorrect command. (bug 29524)
  
  This update fixes these issues.";

tag_affected = "printerdrake on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-11/msg00053.php");
  script_id(830328);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:48:43 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDKA", value: "2007:122");
  script_name( "Mandriva Update for printerdrake MDKA-2007:122 (printerdrake)");

  script_description(desc);
  script_summary("Check for the Version of printerdrake");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"printerdrake", rpm:"printerdrake~1.5.7.2~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"printerdrake-common", rpm:"printerdrake-common~1.5.7.2~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
