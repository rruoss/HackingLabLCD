###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for drakx-net MDVA-2008:190 (drakx-net)
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
tag_affected = "drakx-net on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
tag_insight = "This update adds support for ATM bridging in the network configuration
  tools and backend.  It is mostly used for ADSL pppoe connections with
  USB modems (bug #35797).";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-12/msg00008.php");
  script_id(830392);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVA", value: "2008:190");
  script_name( "Mandriva Update for drakx-net MDVA-2008:190 (drakx-net)");

  script_description(desc);
  script_summary("Check for the Version of drakx-net");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"drakx-net", rpm:"drakx-net~0.36.6~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakx-net-text", rpm:"drakx-net-text~0.36.6~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.63~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdrakx-net", rpm:"libdrakx-net~0.36.6~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"debugmode", rpm:"debugmode~8.81~8.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakx-net", rpm:"drakx-net~0.54.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drakx-net-text", rpm:"drakx-net-text~0.54.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.81~8.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdrakx-net", rpm:"libdrakx-net~0.54.2~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
