############i###################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Ruby on Rails version 2.x before to 2.2.3 and 2.3.x before 2.3.4";
tag_insight = "The flaw is due to error in handling of 'escaping' code for the form
  helpers, which does not properly filter HTML code from user-supplied input
  before displaying the input.";
tag_solution = "Upgrade to Ruby on Rails version 2.2.3 or 2.3.4 or later.
  For updates refer to http://rubyonrails.org/download";
tag_summary = "This host is running Ruby on Rails and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902090);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-3009");
  script_bugtraq_id(36278);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability");
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
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53036");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/product/25856/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2544");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022824.html");
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
if(version_in_range(version:rorVer, test_version:"2.0", test_version2:"2.3.2") ||
   version_in_range(version:rorVer, test_version:"2.3.0", test_version2:"2.3.3")){
 security_warning(port:rorPort);
}
