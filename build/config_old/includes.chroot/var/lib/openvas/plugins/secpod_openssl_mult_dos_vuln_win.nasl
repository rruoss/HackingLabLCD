###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssl_mult_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenSSL DTLS Packets Multiple DOS Vulnerabilities (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause denial-of-service
  conditions,crash the client,and exhaust all memory.
  Impact Level: System/Application";
tag_affected = "OpenSSL version 0.9.8 to version 0.9.8k on Windows.
  OpenSSL version 1.0.0 Beta2 and prior on Windows.";
tag_insight = "Multiple flaws are due to,
  - The library does not limit the number of buffered DTLS records with a
    future epoch.
  - An error when processing DTLS messages can be exploited to exhaust all
    available memory by sending a large number of out of sequence handshake
    messages.
  - A use-after-free error in the 'dtls1_retrieve_buffered_fragment()' function
    can be exploited to cause a crash in a client context.";
tag_solution = "Apply patches or upgrade to the latest version.
  For updates refer tohttp://www.slproweb.com/products/Win32OpenSSL.html";
tag_summary = "This host is running OpenSSL and is prone to Multiple Denial of
  Service Vulnerabilities";

if(description)
{
  script_id(900654);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1377", "CVE-2009-1378","CVE-2009-1379");
  script_bugtraq_id(35001);
  script_name("OpenSSL DTLS Packets Multiple DOS Vulnerabilities (win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35128");
  script_xref(name : "URL" , value : "http://cvs.openssl.org/chngview?cn=18188");

  script_description(desc);
  script_summary("Check for the version of OpenSSL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_win.nasl");
  script_require_keys("OpenSSL/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

opensslVer = get_kb_item("OpenSSL/Win/Ver");
if(!opensslVer){
  exit(0);
}

if(version_in_range(version:opensslVer, test_version:"0.9.8", test_version2:"0.9.8k")){
   security_warning(0);
}
