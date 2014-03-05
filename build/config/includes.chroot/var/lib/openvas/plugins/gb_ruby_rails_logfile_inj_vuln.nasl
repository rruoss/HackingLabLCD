############i###################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_logfile_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ruby on Rails Logfile Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to inject arbitrary data into
  the affected HTTP header field, attackers may be able to launch cross-site
  request-forgery, cross-site scripting, HTML-injection, and other attacks.
  Impact Level: Application";
tag_affected = "Ruby on Rails version 3.0.5";
tag_insight = "The flaw is due to input validation error for the 'X-Forwarded-For'
  field in the header.";
tag_solution = "No solution or patch is available as of 16th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://rubyonrails.org/download";
tag_summary = "This host is running Ruby on Rails and is prone to file
  injection vulnerability.";

if(description)
{
  script_id(801765);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_bugtraq_id(46423);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ruby on Rails Logfile Injection Vulnerability");
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
  script_xref(name : "URL" , value : "https://gist.github.com/868268");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Mar/162");
  script_xref(name : "URL" , value : "http://webservsec.blogspot.com/2011/02/ruby-on-rails-vulnerability.html");

  script_description(desc);
  script_summary("Check for the version of Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
if(rorVer){
 exit(0);
}

## Check Ruby on Rails version
if(version_is_equal(version:rorVer, test_version:"3.0.5")){
 security_warning(port:rorPort);
}
