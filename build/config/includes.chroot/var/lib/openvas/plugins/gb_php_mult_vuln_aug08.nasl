###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln_aug08.nasl 16 2013-10-27 13:09:52Z jan $
#
# Multiple Vulnerabilities in PHP August-08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  security restrictions bypass, access to restricted files, denial of service.
  Impact Level: System";
tag_affected = "PHP version prior to 5.2.6";
tag_insight = "The flaws are caused by,
  - an unspecified stack overflow error in FastCGI SAPI (fastcgi.c).
  - an error during path translation in cgi_main.c.
  - an error with an unknown impact/attack vectors.
  - an unspecified error within the processing of incomplete multibyte
    characters in escapeshellcmd() API function.
  - error in curl/interface.c in the cURL library(libcurl), which could be
    exploited by attackers to bypass safe_mode security restrictions.
  - an error in PCRE. i.e buffer overflow error when handling a character class
    containing a very large number of characters with codepoints greater than
    255(UTF-8 mode).";
tag_solution = "Upgrade to PHP version 5.2.6 or above,
  http://www.php.net/downloads.php";
tag_summary = "The host is installed with PHP, that is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800110);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(29009, 27413, 27786);
  script_cve_id("CVE-2008-2050", "CVE-2008-2051", "CVE-2007-4850",
                "CVE-2008-0599", "CVE-2008-0674");
  script_xref(name:"CB-A", value:"08-0118");
  script_name("Multiple Vulnerabilities in PHP August-08");
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
  script_xref(name : "URL" , value : "http://pcre.org/changelog.txt");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php");
  script_xref(name : "URL" , value : "http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0176");
  script_xref(name : "URL" , value : "http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0178");
  script_xref(name : "URL" , value : "http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0086");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

phpPort = get_kb_item("Services/www");
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

# Debian and Gentoo advisories are available. Once local checks
# are written, we can exit from here.

# Match PHP version < = 5.2.5
if(version_is_less_equal(version:phpVer, test_version:"5.2.5")){
  security_hole(phpPort);
}
