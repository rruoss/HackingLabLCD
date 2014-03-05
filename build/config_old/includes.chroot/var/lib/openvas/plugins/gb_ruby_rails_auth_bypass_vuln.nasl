###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_auth_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Ruby on Rails Authentication Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Apply the security patches
  http://github.com/rails/rails/commit/056ddbdcfb07f0b5c7e6ed8a35f6c3b55b4ab489

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to bypass authentication by
  providing an invalid username with an empty password and gain unauthorized
  access to the system.
  Impact Level: Application";
tag_affected = "Ruby on Rails version 2.3.2 and prior";
tag_insight = "This Flaw is caused During login process, the digest authentication functionality
  (http_authentication.rb) returns a 'nil' instead of 'false' when the provided
  username is not found and then proceeds to verify this value against the
  provided password.";
tag_summary = "The host is running Ruby on Rails, which is prone to Authentication
  Bypass Vulnerability.";

if(description)
{
  script_id(800912);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2422");
  script_bugtraq_id(35579);
  script_name("Ruby on Rails Authentication Bypass Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/35702");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1802");
  script_xref(name : "URL" , value : "http://weblog.rubyonrails.org/2009/6/3/security-problem-with-authenticate_with_http_digest");

  script_description(desc);
  script_summary("Check for the Version of Ruby on Rails");
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


include("http_func.inc");
include("version_func.inc");

railsPort = 3000;

if(!get_port_state(railsPort)){
  exit(0);
}

railsVer = get_kb_item("Ruby-Rails/Linux/Ver");
if(railsVer != NULL)
{
  if(version_is_less_equal(version:railsVer, test_version:"2.3.2")){
    security_hole(railsPort);
  }
}
