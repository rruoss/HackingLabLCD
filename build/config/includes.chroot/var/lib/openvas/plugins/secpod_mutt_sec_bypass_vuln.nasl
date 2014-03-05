###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mutt_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mutt Security Bypass Vulnerability
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
tag_impact = "Successful exploits allow attackers to spoof SSL certificates of trusted
  servers and redirect a user to a malicious web site.
  Impact Level: Application";
tag_affected = "Mutt version 1.5.19 on Linux.";
tag_insight = "When Mutt is linked with OpenSSL or GnuTLS it allows connections
  only one TLS certificate in the chain instead of verifying the entire chain.";
tag_solution = "Apply the patch
  https://bugzilla.redhat.com/show_bug.cgi?id=504979";
tag_summary = "This host has installed Mutt and is prone to Security Bypass
  Vulnerability";

if(description)
{
  script_id(900676);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1390");
  script_bugtraq_id(35288);
  script_name("Mutt Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51068");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/06/10/2");

  script_description(desc);
  script_summary("Checks for the Version of Mutt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_mutt_detect.nasl");
  script_require_keys("Mutt/Ver");
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

muttVer = get_kb_item("Mutt/Ver");
if(muttVer != NULL)
{
  if(version_is_equal(version:muttVer, test_version:"1.5.19")){
    security_hole(0);
  }
}
