###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for lirc MDVA-2008:177 (lirc)
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
tag_insight = "The LIRC packages included with Mandriva Linux 2008 and Mandriva Linux
  2008 Spring did not include the 'commandir' module, which is necessary
  (along with the 'lirc_cmdir' module) to properly support CommandIR
  remote controls.

  These updated packages do include the module.";

tag_affected = "lirc on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-11/msg00024.php");
  script_id(830574);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVA", value: "2008:177");
  script_name( "Mandriva Update for lirc MDVA-2008:177 (lirc)");

  script_description(desc);
  script_summary("Check for the Version of lirc");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"dkms-lirc", rpm:"dkms-lirc~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-lirc-gpio", rpm:"dkms-lirc-gpio~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-lirc-parallel", rpm:"dkms-lirc-parallel~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblirc0", rpm:"liblirc0~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblirc0-devel", rpm:"liblirc0-devel~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc", rpm:"lirc~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lirc0", rpm:"lib64lirc0~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lirc0-devel", rpm:"lib64lirc0-devel~0.8.2~1.20070827.3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"dkms-lirc", rpm:"dkms-lirc~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-lirc-gpio", rpm:"dkms-lirc-gpio~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-lirc-parallel", rpm:"dkms-lirc-parallel~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblirc0", rpm:"liblirc0~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblirc-devel", rpm:"liblirc-devel~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc", rpm:"lirc~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lirc0", rpm:"lib64lirc0~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lirc-devel", rpm:"lib64lirc-devel~0.8.2~1.20080310.2.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
