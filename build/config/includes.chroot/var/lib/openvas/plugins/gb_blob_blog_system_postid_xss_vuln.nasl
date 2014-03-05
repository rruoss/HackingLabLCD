###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blob_blog_system_postid_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# BLOB Blog System 'postid' Parameter XSS Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "BLOB Blog System prior to 1.2 on all platforms.";
tag_insight = "This flaw is due to improper validation of user supplied data passed
  into the 'postid' parameter in the bpost.php.";
tag_solution = "Upgrade to BLOB Blog System 1.2 or later.
  http://sourceforge.net/projects/blobblogsystem/files/";
tag_summary = "This host is running BLOB Blog System and is prone to Cross-Site
  Scripting vulnerability.";

if(description)
{
  script_id(800956);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3594");
  script_name("BLOB Blog System 'postid' Parameter XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35938/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51959");

  script_description(desc);
  script_summary("Check for the version of BLOB Blog System");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_blob_blog_system_detect.nasl");
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

bbsPort = get_http_port(default:80);
if(!bbsPort){
  exit(0);
}

bbsVer = get_kb_item("www/" + bbsPort + "/BLOB-Blog-System");
bbsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:bbsVer);

if(bbsVer[1] != NULL)
{
  if(version_is_less(version:bbsVer[1], test_version:"1.2")){
    security_warning(bbsPort);
  }
}
