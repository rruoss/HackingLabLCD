###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for samba MDVSA-2010:090 (samba)
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
tag_insight = "Multiple vulnerabilies has been found and corrected in samba:

  client/mount.cifs.c in mount.cifs in smbfs in Samba does not verify
  that the (1) device name and (2) mountpoint strings are composed of
  valid characters, which allows local users to cause a denial of service
  (mtab corruption) via a crafted string (CVE-2010-0547).
  
  client/mount.cifs.c in mount.cifs in smbfs in Samba allows local users
  to mount a CIFS share on an  arbitrary mountpoint, and gain privileges,
  via a symlink attack on the mountpoint directory file (CVE-2010-0747).
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "samba on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-05/msg00002.php");
  script_id(831027);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:42:01 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2010:090");
  script_cve_id("CVE-2010-0547", "CVE-2010-0747");
  script_name("Mandriva Update for samba MDVSA-2010:090 (samba)");

  script_description(desc);
  script_summary("Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-vscan-icap", rpm:"samba-vscan-icap~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.0.37~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64talloc1", rpm:"lib64talloc1~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64talloc-devel", rpm:"lib64talloc-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tdb1", rpm:"lib64tdb1~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tdb-devel", rpm:"lib64tdb-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.3.12~0.2mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.4.7~0.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.3.12~0.2mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64talloc1", rpm:"lib64talloc1~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64talloc-devel", rpm:"lib64talloc-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tdb1", rpm:"lib64tdb1~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64tdb-devel", rpm:"lib64tdb-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.3.12~0.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
