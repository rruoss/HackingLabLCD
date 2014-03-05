###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_xss_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Ruby on Rails 'strip_tags' Cross Site Scripting Vulnerability (Linux)
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Apply the security patches or upgrade to Ruby on Rails version 2.3.5
  http://github.com/rails/rails/
  http://rubyonrails.org/download

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site or
  steal cookie-based authentication credentials and launch other attacks.
  Impact Level: Application";
tag_affected = "Ruby on Rails version before 2.3.5";
tag_insight = "This issue is due to the error in 'strip_tagi()' function which is
  not properly escaping non-printable ascii characters.";
tag_summary = "The host is running Ruby on Rails, which is prone to Cross Site
  Scripting Vulnerability.";

if(description)
{
  script_id(801078);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4214");
  script_bugtraq_id(37142);
  script_name("Ruby on Rails 'strip_tags' Cross Site Scripting Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37446");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1023245");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3352");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/11/27/2");

  script_description(desc);
  script_summary("Check for the version of Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ruby_rails_detect.nasl");
  script_require_keys("Ruby-Rails/Linux/Ver");
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

railsPort = 3000;

if(!get_port_state(railsPort)){
  exit(0);
}

railsVer = get_kb_item("Ruby-Rails/Linux/Ver");

if(railsVer){
  if(version_is_less(version:railsVer, test_version:"2.3.5")){
    security_warning(railsPort);
  }
}
