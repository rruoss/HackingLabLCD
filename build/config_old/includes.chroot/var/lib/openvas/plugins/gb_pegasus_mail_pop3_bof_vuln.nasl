###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pegasus_mail_pop3_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pegasus Mail POP3 Response Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  cause the application to crash by sending overly long error responses from
  a remote POP3 server to the affected mail client.
  Impact Level: Application";
tag_affected = "Pegasus Mail 4.51 and prior.";
tag_insight = "A stack based buffer overflow error occus due to improper bounds checking
  when processing POP3 responses.";
tag_solution = "No solution or patch is available as of 05th November, 2009.Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pmail.com/downloads_s3_t.htm";
tag_summary = "This host is running Pegasus Mail which is prone to stack-based
  Buffer Overflow vulnerability.";

if(description)
{
  script_id(800970);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3838");
  script_bugtraq_id(36797);
  script_name("Pegasus Mail POP3 Response Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37134");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3026");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1023075.html");

  script_description(desc);
  script_summary("Check for the version of Pegasus Mail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_pegasus_mail_detect.nasl");
  script_require_keys("Pegasus/Mail/Ver");
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

pmailVer = get_kb_item("Pegasus/Mail/Ver");
if(isnull(pmailVer)){
  exit(0);
}

# Check for version 4.51 (4.5.1.0) and prior.
if(version_is_less_equal(version:pmailVer, test_version:"4.5.1.0")){
  security_hole(0);
}
