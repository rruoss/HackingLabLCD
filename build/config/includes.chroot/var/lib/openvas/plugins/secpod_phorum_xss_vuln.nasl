###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phorum_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Phorum Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_insight = "The flaw is due to error in handling email address.

  NOTE: Further information is not available.";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: Application";
tag_affected = "Phorum version prior to 5.2.15";
tag_solution = "Upgrade Phorum to 5.2.15 or later,
  For updates refer to http://www.phorum.org/downloads.php";
tag_summary = "This host is running Phorum and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902179);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1629");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Phorum Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.facebook.com/note.php?note_id=371190874581");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/16/2");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/18/11");

  script_description(desc);
  script_summary("Check version of Phorum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("phorum_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

phorumPort = get_http_port(default:80);
if(!phorumPort){
  exit(0);
}

phorumVer = get_kb_item(string("www/", phorumPort, "/phorum"));
phorumVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phorumVer);
if(!phorumVer[1]){
  exit(0);
}

# Check for Phorum Version < 5.2.15
if(version_is_less(version:phorumVer[1], test_version:"5.2.15")){
  security_warning(phorumPort);
}
