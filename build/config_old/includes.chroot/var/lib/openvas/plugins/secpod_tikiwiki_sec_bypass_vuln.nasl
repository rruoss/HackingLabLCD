###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tikiwiki_sec_bypass_vuln.nasl 72 2013-11-21 17:10:44Z mime $
#
# TikiWiki Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allows to bypass the authentication process to
  gain unauthorized access to the system with the privileges of the victim.
  Impact Level: Application";
tag_affected = "TikiWiki Version 1.6.1 on all running platform.";
tag_insight = "The flaw is due to improper validation of user login credentials. By
  entering a valid username, an arbitrary or null password, and clicking on the
  'remember me' button.";
tag_solution = "Upgrade to version 1.7.1.1 or latest
  http://info.tikiwiki.org/Get+Tiki";
tag_summary = "The host is installed with TikiWiki and is prone to Authentication
  Bypass vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901002";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 72 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2003-1574");
  script_bugtraq_id(14170);
  script_name("TikiWiki Authentication Bypass Vulnerability");
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
  script_summary("Check for the Version of TikiWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod ");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("TikiWiki/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/40347");
  script_xref(name : "URL" , value : "http://sourceforge.net/tracker/index.php?func=detail&amp;aid=748739&amp;group_id=64258&amp;atid=506846");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

tw_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!tw_port){
  exit(0);
}

tikiVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:tw_port);
if(!tikiVer){
  exit(0);
}

tikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tikiVer);

if(tikiVer[1] != NULL)
{
  if(version_is_equal(version:tikiVer[1], test_version:"1.6.1")){
    security_hole(tw_port);
  }
}
