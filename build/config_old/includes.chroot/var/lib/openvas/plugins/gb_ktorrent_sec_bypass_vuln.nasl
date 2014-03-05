###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ktorrent_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# KTorrent PHP Code Injection And Security Bypass Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary PHP
  code and also bypass security restriction when affected web interface plugin
  is enabled.
  Impact Level: System";
tag_affected = "KTorrent version prior to 3.1.4 on Linux.";
tag_insight = "The flaws are due to
  - sending improperly sanitised request into PHP interpreter. This can be
    exploited by injecting PHP code.
  - web interface plugin does not properly restrict access to the torrent
    upload functionality via HTTP POST request.";
tag_solution = "Upgade to 3.1.4 or higher version
  http://ktorrent.org/";
tag_summary = "This host has KTorrent installed and is prone to Security Bypass
  vulnerability.";

if(description)
{
  script_id(800342);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5905", "CVE-2008-5906");
  script_bugtraq_id(31927);
  script_name("KTorrent PHP Code Injection And Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32442");
  script_xref(name : "URL" , value : "https://bugs.gentoo.org/show_bug.cgi?id=244741");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504178");

  script_description(desc);
  script_summary("Check for the Version of KTorrent");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ktorrent_detect.nasl");
  script_require_keys("KTorrent/Linux/Ver");
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

ktVer = get_kb_item("KTorrent/Linux/Ver");
if(!ktVer){
  exit(0);
}

# Check for version prior to 3.1.4
if(version_is_less(version:ktVer, test_version:"3.1.4")){
  security_hole(0);
}
