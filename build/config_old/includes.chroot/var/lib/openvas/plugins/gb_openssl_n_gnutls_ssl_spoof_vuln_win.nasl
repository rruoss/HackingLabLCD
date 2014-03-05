###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_n_gnutls_ssl_spoof_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker spoof the SSL cerficate and gain
  unauthorized access.";
tag_affected = "OpenSSL version 0.9.8 through 0.9.8k
  GnuTLS version before 2.6.4 and before 2.7.4 on Windows";
tag_insight = "The NSS library used in these applications support MD2 with X.509
  certificates, which allows certificate to be spoofed using MD2 hash collision
  design flaws.";
tag_solution = "Upgrade to OpenSSL 1.0.0 or later and GnuTLS 2.6.4 or 2.7.4 or later.
  http://www.openssl.org/
  http://www.gnu.org/software/gnutls/";
tag_summary = "This host is running OpenSSL/GnuTLS and is prone to SSL server
  spoofing vulnerability.";

if(description)
{
  script_id(800917);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2409");
  script_name("OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Win)");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2009-2409");

  script_description(desc);
  script_summary("Check for the version of OpenSSL/GnuTLS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect_win.nasl", "gb_gnutls_detect_win.nasl");
  script_require_keys("OpenSSL/Win/Ver", "GnuTLS/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include ("version_func.inc");

opensslVer = get_kb_item("OpenSSL/Win/Ver");
if(opensslVer != NULL)
{
  # Grep for OpenSSL version 0.9.8 <= 0.9.8k
  if(version_in_range(version:opensslVer, test_version:"0.9.8",
                                          test_version2:"0.9.8k"))
  {
    security_hole(0);
    exit(0);
  }
}

gnutlsVer = get_kb_item("GnuTLS/Win/Ver");
if(gnutlsVer != NULL)
{
  # Grep for GnuTLS version 2.6.0 < 2.6.4 and 2.7.0 < 2.7.4
  if(version_in_range(version:gnutlsVer, test_version:"2.6.0",
                                        test_version2:"2.6.3")||
     version_in_range(version:gnutlsVer, test_version:"2.7.0",
                                        test_version2:"2.7.3")){
    security_hole(0);
  }
}
