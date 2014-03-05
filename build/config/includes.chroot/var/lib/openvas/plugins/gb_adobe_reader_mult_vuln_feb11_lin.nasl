###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln_feb11_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader Multiple Vulnerabilities February-2011 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let local attackers to obtain elevated
  privileges, or by remote attackers to inject scripting code, or execute
  arbitrary commands by tricking a user into opening a malicious PDF document.
  Impact Level:Application";
tag_affected = "Adobe Reader 9.4.1 and earlier versions for Linux.";
tag_insight = "Multiple flaws are present in Adobe Reader due to insecure permissions,
  input validation errors, memory corruptions, and buffer overflow errors when
  processing malformed contents within a PDF document.";
tag_solution = "Upgrade to Adobe Reader version 9.4.2 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801845);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4091", "CVE-2011-0562", "CVE-2011-0563",
                "CVE-2011-0564", "CVE-2011-0565", "CVE-2011-0566",
                "CVE-2011-0567", "CVE-2011-0568", "CVE-2011-0570",
                "CVE-2011-0585", "CVE-2011-0586", "CVE-2011-0587",
                "CVE-2011-0588", "CVE-2011-0589", "CVE-2011-0590",
                "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593",
                "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596",
                "CVE-2011-0598", "CVE-2011-0599", "CVE-2011-0600",
                "CVE-2011-0602", "CVE-2011-0603", "CVE-2011-0604",
                "CVE-2011-0605", "CVE-2011-0606");
  script_bugtraq_id(46146);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader Multiple Vulnerabilities February-2011 (Linux)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0337");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-03.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
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

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(!readerVer){
  exit(0);
}

# Check for Adobe Reader versions
if(version_is_less(version:readerVer, test_version:"9.4.2")){
    security_hole(0);
}
