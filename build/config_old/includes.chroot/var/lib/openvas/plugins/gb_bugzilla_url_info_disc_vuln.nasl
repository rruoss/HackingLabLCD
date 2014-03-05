###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_url_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Bugzilla URL Password Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  information via the HTTP 'Referrer' header.
  Impact Level: Application";
tag_affected = "Bugzilla version 3.4rc1 to 3.4.1.";
tag_insight = "The flaw is caused because the application places a password in a 'URL' at the
  beginning of a login session that occurs immediately after a password reset,
  which allows context-dependent attackers to discover passwords.";
tag_solution = "Upgrade to Bugzilla version 3.4.2 or later.
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "This host is running Bugzilla and is prone to information disclosure
  vulnerability.";

if(description)
{
  script_id(801413);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-3166");
  script_bugtraq_id(36372);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Bugzilla URL Password Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36718");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022902.html");

  script_description(desc);
  script_summary("Check version for Bugzilla");
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

## Get version from KB
vers = get_version_from_kb(port:port, app:"bugzilla/version");
if(!vers){
 exit(0);
}

## Check Bugzilla version
if(version_in_range(version:vers, test_version: "3.4.rc1", test_version2:"3.4.1")){
 security_warning(port:port);
}
