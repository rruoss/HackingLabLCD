############i###################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_sec_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ruby on Rails Security Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to manipulate arbitrary records.
  Impact Level: Application";
tag_affected = "Ruby on Rails versions 2.3.9 and 3.0.0";
tag_insight = "The flaw is due to an input validation error when handling nested
  attributes, which can be exploited to manipulate arbitrary records by
  changing form input parameter names.";
tag_solution = "Upgrade to Ruby On Rails version 3.0.1 or 2.3.10
  For updates refer to http://rubyonrails.org/download";
tag_summary = "This host is running Ruby on Rails and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(801653);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3933");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ruby on Rails Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41930");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1024624");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2719");
  script_xref(name : "URL" , value : "http://weblog.rubyonrails.org/2010/10/15/security-vulnerability-in-nested-attributes-code-in-ruby-on-rails-2-3-9-and-3-0-0");

  script_description(desc);
  script_summary("Check for the version of Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl");
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

rorPort = "3000";
if(!get_port_state(rorPort)){
  exit(0);
}

## Get version from KB
rorVer = get_kb_item("www/" + rorPort + "/Ruby/Rails/Ver");
if(!rorVer){
  exit(0);
}

## Check Ruby on Rails version
if(version_is_equal(version: rorVer, test_version: "2.3.9") ||
   version_is_equal(version: rorVer, test_version: "3.0.0")) {
  security_hole(port:rorPort);
}
