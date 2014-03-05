###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_insecure_key_generation_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenSC Incorrect RSA Keys Generation Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to obtain the sensitive
  information or gain unauthorized access to the smartcard.
  Impact Level: Application";
tag_affected = "OpenSC version prior to 0.11.8 on Linux.";
tag_insight = "Security issues are due to,
  - a tool that starts a key generation with public exponent set to 1, an
    invalid value that causes an insecure RSA key.
  - a PKCS#11 module that accepts that this public exponent and forwards it
    to the card.
  - a card that accepts the public exponent and generates the rsa key.";
tag_solution = "Upgrade to OpenSC version 0.11.8
  http://www.opensc-project.org/files/opensc";
tag_summary = "This host is installed with OpenSC and is prone to Insecure Key
  Generation vulnerability.";

if(description)
{
  script_id(900639);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1603");
  script_bugtraq_id(34884);
  script_name("OpenSC Incorrect RSA Keys Generation Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35035");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1295");
  script_xref(name : "URL" , value : "http://www.opensc-project.org/pipermail/opensc-announce/2009-May/000025.html");

  script_description(desc);
  script_summary("Check for the version of OpenSC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPOd");
  script_family("Privilege escalation");
  script_dependencies("gb_opensc_detect.nasl");
  script_require_keys("OpenSC/Ver");
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

openscVer = get_kb_item("OpenSC/Ver");
if(openscVer != NULL)
{
  # Check for the version OpenSC < 0.11.8
  if(version_is_less(version:openscVer, test_version:"0.11.8")){
    security_warning(0);
  }
}
