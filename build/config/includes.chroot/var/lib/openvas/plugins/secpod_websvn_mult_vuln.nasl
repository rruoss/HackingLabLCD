###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_websvn_mult_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WebSVN Script Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "This host is running WebSVN and is prone to Multiple
  Vulnerabilities.

  Vulnerability:
  Multiple flaws are due to,
  - input passed in the URL to index.php is not properly sanitised before
    being returned to the user.
  - input passed to the rev parameter in rss.php is not properly sanitised
    before being used, when magic_quotes_gpc is disable.
  - restricted access to the repositories is not properly enforced.";

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the web application and execute cross site scripting attacks and
  can gain sensitive information or can cause directory traversal attacks.
  Impact Level: Application";
tag_affected = "WebSVN version prior to 2.1.0";
tag_solution = "Upgrade to the latest version 2.1.0
  http://websvn.tigris.org/servlets/ProjectDocumentList";

if(description)
{
  script_id(900441);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2008-5920", "CVE-2009-0240");
  script_bugtraq_id(31891);
  script_name("WebSVN Script Multiple Vulnerabilities");
  desc = "

  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32338");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6822");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191");

  script_description(desc);
  script_summary("Check for the version of WebSVN");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_websvn_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

websvnPort = get_kb_item("Services/www");
if(!websvnPort){
  exit(0);
}

if(get_port_state(websvnPort))
{
  svnVer = get_kb_item("www/" + websvnPort + "/WebSVN");
  if(svnVer != NULL)
  {
    # Grep for WebSVN version prior to 2.1.0
    if(version_is_less(version:svnVer, test_version:"2.1.0")){
      security_hole(websvnPort);
    }
  }
}
