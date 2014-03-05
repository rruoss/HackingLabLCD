###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_media_obj_remote_code_exec_vuln_dec09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Reader/Acrobat Multimeda Doc.media.newPlayer Remote Code Execution Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_affected = "Adobe Reader version 9.2.0 and prior.

  Workaround:
  Disable JavaScript execution from the Adobe Acrobat/Reader product
  configuration menu settings.";

tag_insight = "There exists a flaw in the JavaScript module doc.media object while sending
  a null argument to the newPlayer() method as the exploitation method makes
  use of a vpointer that has not been initialized.

  Impact Level: System";

tag_solution = "Upgrade Adobe Reader version 9.3.2 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to
  Doc.media.newPlayer Remote Code Execution vulnerability.";

if(description)
{
  script_id(801095);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4324");
  script_bugtraq_id(37331);
  script_name("Adobe Reader/Acrobat Multimeda Doc.media.newPlayer Remote Code Execution Vulnerability (Linux)");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "
  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.f-secure.com/weblog/archives/00001836.html");
  script_xref(name : "URL" , value : "http://extraexploit.blogspot.com/search/label/CVE-2009-4324");
  script_xref(name : "URL" , value : "http://www.shadowserver.org/wiki/pmwiki.php/Calendar/20091214");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2009/12/new_adobe_reader_and_acrobat_v.html");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/adobe_media_newplayer.rb");
  script_xref(name : "URL" , value : "http://vrt-sourcefire.blogspot.com/2009/12/adobe-reader-medianewplayer-analysis.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version", "");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(readerVer != NULL)
{
  # Check for Adobe Reader version 9.2.0 and prior
  if(version_is_less_equal(version:readerVer, test_version:"9.2.0")){
    security_hole(0);
  }
}
