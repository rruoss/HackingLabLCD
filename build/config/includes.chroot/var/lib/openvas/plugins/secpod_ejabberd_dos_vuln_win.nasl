###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ejabberd_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# ejabberd XML Parsing Denial of Service Vulnerability (Windows)
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
tag_impact = "Successful exploitation allows remote attackers to cause a denial of service.
  Impact Level: Application";
tag_affected = "ejabberd versions before 2.1.7 and 3.x before 3.0.0-alpha-3";
tag_insight = "The flaw is due to an error within the parsing of certain XML input,
  which can be exploited to cause a high CPU and memory consumption via a
  crafted XML document containing a large number of nested entity references.";
tag_solution = "Upgrade to ejabberd version 2.1.7, 3.0.0-alpha-3 or later.
  For updates refer to http://www.ejabberd.im/";
tag_summary = "This host is installed with ejabberd and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(902527);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-1753");
  script_bugtraq_id(48072);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("ejabberd XML Parsing Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44807");
  script_xref(name : "URL" , value : "http://www.ejabberd.im/ejabberd-2.1.7");
  script_xref(name : "URL" , value : "http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.7/");

  script_description(desc);
  script_summary("Check for the version of ejabberd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ejabberd_detect_win.nasl");
  script_require_keys("ejabberd/Win/Ver");
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

## Get version from KB
ver = get_kb_item("ejabberd/Win/Ver");
if(ver)
{
  ver = ereg_replace(pattern:"-", replace:".", string:ver);

  ## Check for ejabberd versions before 2.1.7 and 3.x before 3.0.0-alpha-3
  if(version_is_less(version:ver, test_version:"2.1.7") ||
     version_in_range(version:ver, test_version:"3.0.0", test_version2:"3.0.0.alpha.2")){
    security_warning(0);
  }
}
