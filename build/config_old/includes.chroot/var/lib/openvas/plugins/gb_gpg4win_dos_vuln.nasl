###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gpg4win_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gpg4Win Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "A remote attacker could exploit this vulnerability to cause the application
  to crash.
  Impact Level: Application";
tag_affected = "Gpg4win version 2.0.1
  KDE, Kleopatra version 2.0.11";
tag_insight = "The flaw is due to error in 'gpg2.exe' which can be exploited by
  persuading a victim to import a specially-crafted certificate containing
  an overly long signature.";
tag_summary = "This host is installed with Gpg4Win, as used in KDE Kleopatra and
  is prone to Denial of Service vulnerability.";

tag_solution = "No solution or patch is available as of 02nd November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.gpg4win.org/download.html";

if(description)
{
  script_id(801129);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3805");
  script_bugtraq_id(36781);
  script_name("Gpg4Win Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53908");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.com/0910-exploits/gpg2kleo-dos.txt");

  script_description(desc);
  script_summary("Check for the version of Gpg4Win and Kleopatra");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_gpg4win_detect.nasl");
  script_require_keys("Gpg4win/Win/Ver", "Kleopatra/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Get KB for Gpg4win
gpgVer = get_kb_item("Gpg4win/Win/Ver");

# Get KB for Kleopatra
kleoVer = get_kb_item("Kleopatra/Win/Ver");

# Check for Gpg4win version 2.0.1 and Kleopatar version 2.0.11
if(version_is_equal(version:gpgVer, test_version:"2.0.1") &&
   version_is_equal(version:kleoVer,test_version:"2.0.11")){
  security_warning(0);
}
