###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for bluez-utils MDKSA-2007:014 (bluez-utils)
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
tag_insight = "hidd in BlueZ (bluez-utils) before 2.25 allows remote attackers to
  obtain control of the (1) Mouse and (2) Keyboard Human Interface Device
  (HID) via a certain configuration of two HID (PSM) endpoints, operating
  as a server, aka HidAttack.

  hidd is not enabled by default on Mandriva 2006.0. This update adds the
  --nocheck option (disabled by default) to the hidd binary, which
  defaults to rejecting connections from unknown devices unless --nocheck
  is enabled.
  
  The updated packages have been patched to correct this problem";

tag_affected = "bluez-utils on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-01/msg00023.php");
  script_id(830165);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDKSA", value: "2007:014");
  script_cve_id("CVE-2006-6899");
  script_name( "Mandriva Update for bluez-utils MDKSA-2007:014 (bluez-utils)");

  script_description(desc);
  script_summary("Check for the Version of bluez-utils");
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

if(release == "MNDK_2006.0")
{

  if ((res = isrpmvuln(pkg:"bluez-utils", rpm:"bluez-utils~2.19~7.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bluez-utils-cups", rpm:"bluez-utils-cups~2.19~7.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
