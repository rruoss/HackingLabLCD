###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for udunits2 FEDORA-2010-17819
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
tag_insight = "The Unidata units utility, udunits2, supports conversion of unit specifications
  between formatted and binary forms, arithmetic manipulation of unit
  specifications, and conversion of values between compatible scales of
  measurement. A unit is the amount by which a physical quantity is measured. For
  example:

                    Physical Quantity   Possible Unit
                    _________________   _____________
                          time              weeks
                        distance         centimeters
                          power             watts
  
  This utility works interactively and has two modes. In one mode, both an input
  and output unit specification are given, causing the utility to print the
  conversion between them. In the other mode, only an input unit specification is
  given. This causes the utility to print the definition -- in standard units --
  of the input unit.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "udunits2 on Fedora 14";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-November/051405.html");
  script_id(862594);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-02 08:39:14 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2010-17819");
  script_cve_id("CVE-2009-3720");
  script_name("Fedora Update for udunits2 FEDORA-2010-17819");

  script_description(desc);
  script_summary("Check for the Version of udunits2");
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"udunits2", rpm:"udunits2~2.1.19~1.fc14", rls:"FC14")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
