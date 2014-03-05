###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpbb_sec_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpBB 'feed.php' Security Bypass Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to bypass intended access
  restrictions via unspecified attack vectors.
  Impact Level: Application";
tag_affected = "phpBB version 3.0.7 before 3.0.7-PL1";
tag_insight = "The flaw is due to error in 'feed.php', which does not properly check
  permissions for feeds.";
tag_solution = "Upgrade phpBB to 3.0.7-PL1 or later,
  For updates refer to http://www.phpbb.com/downloads/";
tag_summary = "This host is running phpBB and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(902180);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1627");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Phorum 'feed.php' Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/16/1");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/18/6");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/05/18/12");

  script_description(desc);
  script_summary("Check version of phpBB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
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

phpBBPort = get_http_port(default:80);
if(!phpBBPort){
  exit(0);
}

phpBBVer = get_kb_item(string("www/", phpBBPort, "/phpBB"));
if(isnull(phpBBVer)){
  exit(0);
}

phpBBVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpBBVer);
if(!isnull(phpBBVer[1]))
{
  phpBBVer = ereg_replace(pattern:"-", replace:".", string:phpBBVer[1]);

  # Check for phpBB Version < 3.0.7.PL1
  if(phpBBVer =~ "^3\.0\.7\.*")
  {
    if(version_is_less(version:phpBBVer, test_version:"3.0.7.PL1")){
      security_warning(phpBBPort);
    }
  }
}
