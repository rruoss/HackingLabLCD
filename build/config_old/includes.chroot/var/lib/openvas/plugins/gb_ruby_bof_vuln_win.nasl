###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ruby 'ARGF.inplace_mode' Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allows local attackers to cause buffer overflow
  and execute arbitrary code on the system or cause the application to crash.
  Impact Level: Application.";
tag_affected = "Ruby version 1.9.x before 1.9.1-p429 on Windows.";

tag_insight = "The flaw caused by improper bounds checking when handling filenames on Windows
  systems. It is not properly validating value assigned to the 'ARGF.inplace_mode'
  variable.";
tag_solution = "Upgrade to Ruby version 1.9.1-p429 or later,
  For updates refer to http://rubyforge.org/frs/?group_id=167";
tag_summary = "This host is installed with Ruby and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(801375);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2489");
  script_bugtraq_id(41321);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ruby 'ARGF.inplace_mode' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/66040");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40442");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60135");
  script_xref(name : "URL" , value : "http://svn.ruby-lang.org/repos/ruby/tags/v1_9_1_429/ChangeLog");

  script_description(desc);
  script_summary("Check for the version of Ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_require_keys("Ruby/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

rubyVer = get_kb_item("Ruby/Win/Ver");
if(!rubyVer){
  exit(0);
}

# Grep for Ruby Interpreter version from 1.9.0 to 1.9.1 Patch Level 428
if(version_in_range(version:rubyVer, test_version:"1.9.0",
                                     test_version2:"1.9.1.p428")){
  security_hole(0);
}
