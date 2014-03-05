###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_safe_buffer_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ruby on Rails 'Safe Buffer' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_solution = "Upgrade to Ruby on Rails version 2.3.12 or 3.0.8 or 3.1.0.rc2 or later.
  For updates refer to http://rubyonrails.org/download

  Apply the patch for Ruby on Rails versions 3.1.0.rc1, 3.0.7 and 2.3.11 from
  below link.
  http://weblog.rubyonrails.org/2011/6/8/potential-xss-vulnerability-in-ruby-on-rails-applications";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Ruby on Rails version 2.x before 2.3.12, 3.0.x before 3.0.8 and
  3.1.x before 3.1.0.rc2.";
tag_insight = "The flaw is due to certain methods not properly handling the
  'HTML safe' mark for strings, which can lead to improperly sanitised input
  being returned to the user.";
tag_summary = "This host is running Ruby on Rails and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(802115);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_cve_id("CVE-2011-2197");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ruby on Rails 'Safe Buffer' Cross-Site Scripting Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/44789");
  script_xref(name : "URL" , value : "http://weblog.rubyonrails.org/2011/6/8/potential-xss-vulnerability-in-ruby-on-rails-applications");

  script_description(desc);
  script_summary("Check for the version of Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl");
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

rorPort = "3000";
if(!get_port_state(rorPort)){
  exit(0);
}

## Get version from KB
rorVer = get_kb_item("www/" + rorPort + "/Ruby/Rails/Ver");
if(rorVer){
 exit(0);
}

## Check Ruby on Rails version
if(version_in_range(version:rorVer, test_version:"2.0", test_version2:"2.3.11") ||
   version_in_range(version:rorVer, test_version:"3.0", test_version2:"3.0.7") ||
   version_in_range(version:rorVer, test_version:"3.1", test_version2:"3.1.0.rc1")){
  security_warning(port:rorPort);
}
