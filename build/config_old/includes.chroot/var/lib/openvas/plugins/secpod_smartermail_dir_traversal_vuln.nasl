###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SmarterMail Directory Traversal Vulnerability
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
tag_solution = "No solution or patch is available as of 28th September, 2010. Information
  regarding this issue will update once the solution details are available.
  For updates refer to http://www.smartertools.com/smartermail/mail-server-software.aspx

  http://netwinsite.com/download.htm";

tag_impact = "Successful exploitation could allow remote authenticated users to read and
  write directories, files and perform malicious operations.
  Impact Level: Application";
tag_affected = "SmarterTools SmarterMail 7.1.x";
tag_insight = "The flaw is due to error in the 'FileStorageUpload.ashx', which fails
  to validate the input value passed to the 'name' parameter. This allows
  remote attackers to read arbitrary files via a '../' or '%5C' or '%255c'
  in the name parameter.";
tag_summary = "This host is running SmarterMail and is prone to directory trversal
  vulnerability.";

if(description)
{
  script_id(902259);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-3486");
  script_bugtraq_id(43324);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SmarterMail Directory Traversal Vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61910");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15048/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/smartermail-traversal.txt");
  script_xref(name : "URL" , value : "http://cloudscan.blogspot.com/2010/09/smarter-stats-533819-file-fuzzing.html");

  script_description(desc);
  script_summary("Check for the version of SmarterMail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_keys("SmartMail/Ver");
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

# Grep for SmartMail
smVer = get_kb_item("SmartMail/Ver");
if(!isnull(smVer))
{
  # Check for SurgeMail SmartMail
  if(version_is_less(version:surgemailVer, test_version:"7.2")){
    security_warning(0);
  }
}
