###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Bugzilla 'localconfig' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to read sensitive
  configuration fields.
  Impact Level: Application";
tag_affected = "Bugzilla version 3.5.1 to 3.6 and 3.7";
tag_insight = "The flaw is due to an error in 'install/Filesystem.pm', which uses
  world readable permissions for the localconfig files via the database
  password field and the site_wide_secret field.";
tag_solution = "Upgrade to Bugzilla version 3.6.1, 3.7.1 or later,
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "This host is running Bugzilla and is prone to information disclosure
  vulnerability.";

if(description)
{
  script_id(801367);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-0180");
  script_bugtraq_id(41144);
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_name("Bugzilla 'localconfig' Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40300");
  script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.2.6/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1595");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=561797");

  script_description(desc);
  script_summary("Determine if running Bugzilla version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

vers = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!vers){
 exit(0);
}

if(version_is_equal(version:vers, test_version:"3.7") ||
   version_in_range(version:vers, test_version: "3.5.1", test_version2:"3.6")){
 security_note(port:port);
}
