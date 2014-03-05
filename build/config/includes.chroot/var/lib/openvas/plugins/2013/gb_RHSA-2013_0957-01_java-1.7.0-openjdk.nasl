###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for java-1.7.0-openjdk RHSA-2013:0957-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  Multiple flaws were discovered in the ImagingLib and the image attribute,
  channel, layout and raster processing in the 2D component. An untrusted
  Java application or applet could possibly use these flaws to trigger Java
  Virtual Machine memory corruption. (CVE-2013-2470, CVE-2013-2471,
  CVE-2013-2472, CVE-2013-2473, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469)

  Integer overflow flaws were found in the way AWT processed certain input.
  An attacker could use these flaws to execute arbitrary code with the
  privileges of the user running an untrusted Java applet or application.
  (CVE-2013-2459)

  Multiple improper permission check issues were discovered in the Sound,
  JDBC, Libraries, JMX, and Serviceability components in OpenJDK. An
  untrusted Java application or applet could use these flaws to bypass Java
  sandbox restrictions. (CVE-2013-2448, CVE-2013-2454, CVE-2013-2458,
  CVE-2013-2457, CVE-2013-2453, CVE-2013-2460)

  Multiple flaws in the Serialization, Networking, Libraries and CORBA
  components can be exploited by an untrusted Java application or applet to
  gain access to potentially sensitive information. (CVE-2013-2456,
  CVE-2013-2447, CVE-2013-2455, CVE-2013-2452, CVE-2013-2443, CVE-2013-2446)

  It was discovered that the Hotspot component did not properly handle
  out-of-memory errors. An untrusted Java application or applet could
  possibly use these flaws to terminate the Java Virtual Machine.
  (CVE-2013-2445)

  It was discovered that the AWT component did not properly manage certain
  resources and that the ObjectStreamClass of the Serialization component
  did not properly handle circular references. An untrusted Java application
  or applet could possibly use these flaws to cause a denial of service.
  (CVE-2013-2444, CVE-2013-2450)

  It was discovered that the Libraries component contained certain errors
  related to XML security and the class loader. A remote attacker could
  possibly exploit these flaws to bypass intended security mechanisms or
  disclose potentially sensitive information and cause a denial of service.
  (CVE-2013-2407, CVE-2013-2461)

  It was discovered that JConsole did not properly inform the user when
  establishing an SSL connection failed. An attacker could exploit this flaw
  to gain access to potentially sensitive information. (CVE-2013-2412)

  It was discovered that GnomeFi ...

  Description truncated, for more information please check the Reference URL";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "java-1.7.0-openjdk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  desc = "

    Vulnerability Insight:
    " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "insight" , value : tag_insight);
  }
  script_id(871010);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-24 14:55:53 +0530 (Mon, 24 Jun 2013)");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412",
                "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446",
                "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450",
                "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455",
                "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459",
                "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465",
                "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472",
                "CVE-2013-2473");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("RedHat Update for java-1.7.0-openjdk RHSA-2013:0957-01");

  script_description(desc);
  script_xref(name: "RHSA", value: "2013:0957-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-June/msg00017.html");
  script_summary("Check for the Version of java-1.7.0-openjdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.25~2.3.10.3.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.25~2.3.10.3.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.25~2.3.10.3.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}