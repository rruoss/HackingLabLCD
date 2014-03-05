###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qip_icq_message_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Qip ICQ Message Denial Of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers may exploit this issue to crash the application.
  Impact Level: Application";
tag_affected = "QIP version 2005 build 8082 and prior on Windows";
tag_insight = "Issue generated due to an error in handling Rich Text Format ICQ messages.";
tag_solution = "Upgrade to latest version
  http://qip.ru/ru/pages/download_qip_ru/";
tag_summary = "This host is installed with QIP and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(800541);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0769");
  script_bugtraq_id(33609);
  script_name("Qip ICQ Message Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33851");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500656/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of QIP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_qip_detect.nasl");
  script_require_keys("QIP/Version");
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

qipVer = get_kb_item("QIP/Version");
if(!qipVer){
  exit(0);
}

if(version_is_less_equal(version:qipVer, test_version:"8.0.8.2")){
  security_warning(0);
}
