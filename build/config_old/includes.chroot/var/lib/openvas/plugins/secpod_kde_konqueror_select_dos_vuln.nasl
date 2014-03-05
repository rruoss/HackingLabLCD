###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kde_konqueror_select_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# KDE Konqueror Select Object Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
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
tag_impact = "Successful exploitation will lead to memory consumption and can result in
  a browser crash.";
tag_affected = "KDE Konqueror version 4.2.4 and prior.";
tag_insight = "The flaw occurs due to an error while processing Select object whose length
  property contains a large integer value.";
tag_solution = "Upgrade to KDE Konqueror version 4.4.3 or later.
  For updates refer to http://www.kde.org/download";
tag_summary = "This host is installed with KDE Konqueror and is prone to Denial
  of Service Vulnerability.";

if(description)
{
  script_id(900903);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2537");
  script_name("KDE Konqueror Select Object Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9160");
  script_xref(name : "URL" , value : "http://www.g-sec.lu/one-bug-to-rule-them-all.html");

  script_description(desc);
  script_summary("Check for the version of Konqueror");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_kde_konqueror_detect.nasl");
  script_require_keys("KDE/Konqueror/Ver");
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

konqerVer = get_kb_item("KDE/Konqueror/Ver");

if(konqerVer != NULL)
{
  # Grep for version 4.2.4  or prior
  if(version_is_less_equal(version:konqerVer, test_version:"4.2.4")){
    security_warning(0);
  }
}
