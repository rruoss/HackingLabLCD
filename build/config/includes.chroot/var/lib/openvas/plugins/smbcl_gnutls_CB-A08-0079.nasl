# OpenVAS Vulnerability Test
# $Id: smbcl_gnutls_CB-A08-0079.nasl 16 2013-10-27 13:09:52Z jan $
# Description: GnuTLS < 2.2.4 vulnerability (Win)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Modified to implement through 'smb_nt.inc'
#- By Nikita MR <rnikita@secpod.com> on 2009-09-17
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is probably affected by the vulnerabilities described in
 CVE-2008-1948, CVE-2008-1949, CVE-2008-1950

GnuTLS < 2.2.4 vulnerability

Impact

   CVE-2008-1948
     The _gnutls_server_name_recv_params function in lib/ext_server_name.c
     in libgnutls in gnutls-serv in GnuTLS before 2.2.4 does not properly
     calculate the number of Server Names in a TLS 1.0 Client Hello
     message during extension handling, which allows remote attackers
     to cause a denial of service (crash) or possibly execute arbitrary
     code via a zero value for the length of Server Names, which leads
     to a buffer overflow in session resumption data in the
     pack_security_parameters function, aka GNUTLS-SA-2008-1-1.

   CVE-2008-1949
     The _gnutls_recv_client_kx_message function in lib/gnutls_kx.c
     in libgnutls in gnutls-serv in GnuTLS before 2.2.4 continues to
     process Client Hello messages within a TLS message after one has
     already been processed, which allows remote attackers to cause a
     denial of service (NULL dereference and crash) via a TLS message
     containing multiple Client Hello messages, aka GNUTLS-SA-2008-1-2.

   CVE 2008-1950
     Integer signedness error in the _gnutls_ciphertext2compressed
     function in lib/gnutls_cipher.c in libgnutls in GnuTLS before 2.2.4
     allows remote attackers to cause a denial of service (buffer over-read
     and crash) via a certain integer value in the Random field in an
     encrypted Client Hello message within a TLS record with an invalid
     Record Length, which leads to an invalid cipher padding length,
     aka GNUTLS-SA-2008-1-3.";

tag_solution = "All GnuTLS users should upgrade to the latest version.";

# $Revision: 16 $

if(description)
{

 script_id(90027);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-06 20:50:27 +0200 (Sat, 06 Sep 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2008-1948");
 script_name("GnuTLS < 2.2.4 vulnerability (Win)");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1948");
 script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1949");
 script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1950");

 script_description(desc);
 script_summary("Determines GnuTLS < 2.2.4 vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
 script_family("General");
 script_dependencies("gb_gnutls_detect_win.nasl");
 script_require_keys("GnuTLS/Win/Ver");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include ("version_func.inc");

gnutlsVer = get_kb_item("GnuTLS/Win/Ver");
if(gnutlsVer != NULL)
{
  if(version_is_less(version:gnutlsVer, test_version:"2.2.4")){
    security_hole(0);
  }
}
