###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_replay_attack_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Tor Replay Attack Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will let the remote attacker cause replay attacks
  in the network and can compromise router functionalities.

  Impact level: Network";

tag_affected = "Tor version 0.2.0.34 and prior on Windows.";
tag_insight = "Flaw is in the data flow at the end of the circuit which lets the attacker
  to modify the relayed data.";
tag_solution = "Upgrade to Tor version 0.2.1.25 or later,
  For updates refer to https://www.torproject.org";
tag_summary = "This host is installed with Tor Anonimity Proxy and is prone
  to replay attack vulnerability.";

if(description)
{
  script_id(900322);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0654");
  script_name("Tor Replay Attack Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://blog.torproject.org/blog/one-cell-enough");
  script_xref(name : "URL" , value : "http://www.blackhat.com/presentations/bh-dc-09/Fu/BlackHat-DC-09-Fu-Break-Tors-Anonymity.pdf");

  script_description(desc);
  script_summary("Check for the version of Tor Proxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(torVer != NULL)
{
  # Grep for version 0.2.0.34 and prior
  if(version_is_less_equal(version:torVer, test_version:"0.2.0.34")){
    security_hole(0);
  }
}
