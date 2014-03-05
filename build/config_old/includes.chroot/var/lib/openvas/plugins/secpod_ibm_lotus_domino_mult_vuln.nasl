###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  in the context of the Lotus Domino server process or bypass authentication.
  Impact Level: Application/System";
tag_affected = "IBM Lotus Domino versions 8.5.3 prior";
tag_insight = "Multiple flaws are due to,
   - Stack overflow in the SMTP service, which allows remote attackers to
     execute arbitrary code via long arguments in a filename parameter in a
     malformed MIME e-mail message.
   - Buffer overflow in nLDAP.exe, which allows remote attackers to execute
     arbitrary code via an LDAP Bind operation.
   - Stack  overflow in the NRouter service, which allows remote attackers to
     execute arbitrary code via long filenames associated with Content-ID and
     ATTACH:CID headers in attachments in malformed calendar-request e-mail
     messages.
   - Multiple stack overflows in the POP3 and IMAP services, which allows
     remote attackers to execute arbitrary code via non-printable characters
     in an envelope sender address.
   - The Remote Console, when a certain unsupported configuration involving UNC
     share pathnames is used, allows remote attackers to bypass authentication
     and execute arbitrary code via unspecified vectors.";
tag_solution = "No solution or patch is available as of 28th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902419);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-0916","CVE-2011-0918", "CVE-2011-0919", "CVE-2011-0920");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Domino Multiple Remote Buffer Overflow Vulnerabilities");
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


  script_description(desc);
  script_summary("Check for the version of IBM Lotus Domino");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_lotus_domino_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43247");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43224");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-045/");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-049/");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-047/");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-046/");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21461514");
  script_xref(name : "URL" , value : "http://www.protekresearchlab.com/index.php?option=com_content&amp;view=article&amp;id=23&amp;Itemid=23");
  exit(0);
}


include("version_func.inc");

## Get Lotus Domino Version from KB
domVer = get_kb_item("Domino/Version");
domPort = get_kb_item("Domino/Port/");
if(!domVer || !domPort){
  exit(0);
}

## Check for Vulnerable Lotus Domino Versions
if(version_is_less_equal(version:domVer, test_version:"8.5.3")){
  security_hole(domPort);
}
