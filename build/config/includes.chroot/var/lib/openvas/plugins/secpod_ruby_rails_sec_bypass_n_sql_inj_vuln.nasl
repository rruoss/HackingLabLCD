###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_sec_bypass_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ruby on Rails Security Bypass and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions and conduct SQL injection attacks.
  Impact Level: Application";
tag_affected = "Ruby on Rails versions 3.x before 3.0.4";
tag_insight = "- The filtering code does not properly work for case insensitive file
    systems, which can be exploited to bypass the filter by varying the case
    in certain action parameters.
  - Input passed to the 'limit()' function is not properly sanitised before
    being used in SQL queries. This can be exploited to manipulate SQL queries
    by injecting arbitrary SQL code.";
tag_solution = "Upgrade to Ruby on Rails version 3.0.4 or later.
  For updates refer to http://rubyonrails.org/download";
tag_summary = "This host is running Ruby on Rails and is prone to security bypass
  and SQL injection vulnerabilities.";

if(description)
{
  script_id(901187);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-0448", "CVE-2011-0449");
  script_bugtraq_id(46292);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ruby on Rails Security Bypass and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43278");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025063");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025061");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0343");

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
if(version_in_range(version: rorVer, test_version:"3.0.0", test_version2:"3.0.3")){
  security_hole(port:rorPort);
}
