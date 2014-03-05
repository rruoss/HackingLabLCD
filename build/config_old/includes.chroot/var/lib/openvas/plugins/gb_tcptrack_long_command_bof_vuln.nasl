###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcptrack_long_command_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Tcptrack Command Line Parsing Heap Based Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code via a long
  command line argument in the LWRES dissector when processing malformed data
  or packets.
  Impact Level: System/Application";
tag_affected = "Tcptrack version prior to 1.4.2";
tag_insight = "The flaw is caused  due to error in command line parsing, it is not properly
  handling long command line argument.";
tag_solution = "Upgrade to Tcptrack 1.4.2 or later,
  For updates refer to http://www.rhythm.cx/~steve/devel/tcptrack/#gettingit";
tag_summary = "This host is installed with Tcptrack and is prone to heap based
  buffer overflow vulnerability.";

if(description)
{
  script_id(801973);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-13 07:51:43 +0200 (Tue, 13 Sep 2011)");
  script_cve_id("CVE-2011-2903");
  script_bugtraq_id(49352);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Tcptrack Command Line Parsing Heap Based Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2011/q3/293");
  script_xref(name : "URL" , value : "https://bugs.gentoo.org/show_bug.cgi?id=377917");
  script_xref(name : "URL" , value : "http://www.rhythm.cx/~steve/devel/tcptrack/#news");

  script_description(desc);
  script_summary("Check for the version of Tcptrack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_tcptrack_detect.nasl");
  script_family("Buffer overflow");
  script_require_keys("Tcptrack/Ver");
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

## Get the version from kb
tcpVer = get_kb_item("Tcptrack/Ver");
if(!tcpVer){
  exit(0);
}

## Check the version
if(version_is_less(version:tcpVer, test_version:"1.4.2")){
  security_hole(0);
}
