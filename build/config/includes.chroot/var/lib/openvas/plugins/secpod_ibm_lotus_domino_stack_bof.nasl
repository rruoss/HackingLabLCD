###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_lotus_domino_stack_bof.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM Lotus Domino iCalendar Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  in the context of the 'nrouter.exe' Lotus Domino server process. Failed
  attacks will cause denial-of-service conditions.
  Impact Level: Application/System";
tag_affected = "IBM Lotus Domino Versions 8.0.x before 8.0.2 FP5 and 8.5.x before 8.5.1 FP2";
tag_insight = "The flaw is due to a boundary error in the 'MailCheck821Address()'
  function within nnotes.dll when copying an email address using the
  'Cstrcpy()' library function. This can be exploited to cause a stack-based
  buffer overflow via an overly long 'ORGANIZER:mailto' iCalendar header.";
tag_solution = "Upgrade to IBM Lotus Domino version 8.5.2, 8.5.1 Fix Pack 2 or 8.0.2 Fix Pack 5,
  For updates refer to http://www-01.ibm.com/software/lotus/products/domino/";
tag_summary = "The host is running IBM Lotus Domino Server and is prone to remote
  stack buffer overflow vulnerability.";

if(description)
{
  script_id(901157);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_bugtraq_id(43219);
  script_cve_id("CVE-2010-3407");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("IBM Lotus Domino iCalendar Remote Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15005");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2381");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Sep/1024448.html");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21446515");

  script_description(desc);
  script_summary("Check for the version of IBM Lotus Domino");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_lotus_domino_detect.nasl");
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

## Get Lotus Domino Version from KB
domVer = get_kb_item("Domino/Version");
domPort = get_kb_item("Domino/Port/");
if(!domVer || !domPort){
  exit(0);
}

domVer = ereg_replace(pattern:"FP", string:domVer, replace: ".FP");

## Check for Vulnerable Lotus Domino Versions
if(version_in_range(version:domVer, test_version:"8", test_version2:"8.0.2.FP4") ||
   version_in_range(version:domVer, test_version:"8.5", test_version2:"8.5.1.FP1")){
  security_hole(domPort);
}
