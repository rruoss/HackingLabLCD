###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_mod_jk_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache Tomcat mod_jk Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "This issue can be exploited to disclose response data associated with the
  request of a different user via specially crafted HTTP requests and to gain
  sensitive information about the remote host.
  Impact Level: Application";
tag_affected = "Apache Tomcat mod_jk version 1.2.0 to 1.2.26";
tag_insight = "This flaw is due to
  - an error when handling empty POST requests with a non-zero 'Content-Length'
    header.
  - an error while handling multiple noncompliant AJP protocol related requests.";
tag_solution = "Upgrade to mod_jk 1.2.27 or later.
  http://svn.eu.apache.org/viewvc?view=rev&revision=702540";
tag_summary = "This host is running Apache Tomcat with mod_jk Module and is prone to
  Information Disclosure vulnerability.";

if(description)
{
  script_id(800277);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5519");
  script_bugtraq_id(34412);
  script_name("Apache Tomcat mod_jk Information Disclosure Vulnerability");
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
  script_summary("Check version of Apache Module mod_jk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_mod_jk_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34621");
  script_xref(name : "URL" , value : "http://marc.info/?l=tomcat-dev&amp;m=123913700700879");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Apr/1022001.html");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

modjkVer = get_kb_item("www/" + port + "/Apache/Mod_Jk");
if(modjkVer == NULL){
  exit(0);
}

if(version_in_range(version:modjkVer, test_version:"1.2.0", test_version2:"1.2.26"))
{
  security_warning(port);
  exit(0);
}
