###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_discloser_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Discloser 'more' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow execution of arbitrary SQL commands in
  the affected application.
  Impact Level: Application";
tag_affected = "Discloser version 0.0.4 rc2";
tag_insight = "The flaw is due to input validation error in the 'index.php' script when
  processing the 'more' parameter.";
tag_solution = "No solution or patch is available as of 22nd March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://discloser.sourceforge.net/";
tag_summary = "The host is running Discloser and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902138);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4719");
  script_bugtraq_id(35923);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Discloser 'more' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9349");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/505478/100/0/threaded");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check version of Discloser");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_discloser_detect.nasl");
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

discport = get_http_port(default:80);
if(!discport){
  exit(0);
}

discver = get_kb_item("www/" + discport + "/Discloser");
if(isnull(discver)){
  exit(0);
}

discver = eregmatch(pattern:"^(.+) under (/.*)$", string:discver);
if(!isnull(discver[1]))
{
  # Discloser version 0.0.4 rc2
   if(version_is_equal(version:discver[1], test_version:"0.0.4.rc2")){
    security_hole(discport);
  }
}
