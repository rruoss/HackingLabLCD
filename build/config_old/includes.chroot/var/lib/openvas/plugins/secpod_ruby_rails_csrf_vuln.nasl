###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ruby on Rails Cross Site Request Forgery Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to conduct cross site request
  forgery attacks by using combinations of browser plugins and HTTP redirections.
  Impact Level: Application";
tag_affected = "Ruby on Rails versions 2.1.x, 2.2.x, and 2.3.x before 2.3.11, and 3.x before 3.0.4";
tag_insight = "The flaw is caused by input validation errors in the CSRF protection feature,
  which could allow attackers to conduct cross site request forgery attacks by
  using combinations of browser plugins and HTTP redirections.";
tag_solution = "Upgrade to Ruby on Rails version 3.0.4 or 2.3.11.
  For updates refer to http://rubyonrails.org/download";
tag_summary = "This host is running Ruby on Rails and is prone to cross site
  request forgery vulnerabilities.";

if(description)
{
  script_id(901184);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2011-0447");
  script_bugtraq_id(46291);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ruby on Rails Cross Site Request Forgery Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0343");
  script_xref(name : "URL" , value : "http://groups.google.com/group/rubyonrails-security/msg/365b8a23b76a6b4a?dmode=source&amp;output=gplain");
  exit(0);
}


include("version_func.inc");

rorPort = "3000";
if(!get_port_state(rorPort)){
  exit(0);
}

## Get version from KB
rorVer = get_kb_item("www/" + rorPort + "/Ruby/Rails/Ver");
if(! rorVer){
  exit(0);
}

## Check Ruby on Rails version
if(version_in_range(version: rorVer, test_version:"2.1", test_version2:"2.3.10") ||
   version_in_range(version: rorVer, test_version:"3.0.0", test_version2:"3.0.3")){
  security_hole(port:rorPort);
}
