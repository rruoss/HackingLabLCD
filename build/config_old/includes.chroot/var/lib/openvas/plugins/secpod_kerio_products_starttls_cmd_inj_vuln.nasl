###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kerio_products_starttls_cmd_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Kerio Products 'STARTTLS' Plaintext Command Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary commands
  in the context of the user running the application.
  Impact Level: Application";
tag_affected = "Kerio MailServer versions 6.x
  Kerio Connect version 7.1.4 build 2985";
tag_insight = "This flaw is caused by an error within the 'STARTTLS' implementation where
  the switch from plaintext to TLS is implemented below the application's I/O
  buffering layer, which could allow attackers to inject commands during the
  plaintext phase of the protocol via man-in-the-middle attacks.";
tag_solution = "No solution or patch is available as of 23rd March, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.kerio.com/connect/download";
tag_summary = "The host is running Kerio Mail Server/Connect and is prone to
  plaintext command injection vulnerability.";

if(description)
{
  script_id(901194);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-1506");
  script_bugtraq_id(46767);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Kerio Products 'STARTTLS' Plaintext Command Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43678");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0610");

  script_description(desc);
  script_summary("Check for the version of Kerio Mail Server/Connect");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_require_keys("KerioMailServer/Ver");
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

## Get Kerio Mail Server/Connect Version.
kerioVer = get_kb_item("KerioMailServer/Ver");
if(!kerioVer){
  exit(0);
}

## Chek for the Kerio Mail Server/Connect Versions
if(version_in_range(version:kerioVer, test_version:"6.0", test_version2:"6.7.3.patch1") ||
   version_is_equal(version:kerioVer, test_version:"7.1.4")){
  security_hole(0);
}
