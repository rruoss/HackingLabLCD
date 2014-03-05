###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_xss_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Kerio MailServer WebMail 'Integration' Page XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could result in insertion of arbitrary HTML and script
  code in the user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Kerio MailServer version 6.6.0 before 6.6.2 Patch 3 and
                           6.7.0 before 6.7.0 Patch 1";
tag_insight = "Issue is due to certain unspecified input passed to the integration page of
  the WebMail component which is not properly sanitised before being returned
  to the user.";
tag_solution = "Upgrade to Kerio MailServer 6.6.2 Patch 3 or 6.7.0 Patch 1 or later
  http://www.kerio.com/kms_download.html";
tag_summary = "The host is running Kerio MailServer and is prone to Cross-Site
  Scripting vulnerability";

if(description)
{
  script_id(800675);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2636");
  script_bugtraq_id(35264);
  script_name("Kerio MailServer WebMail 'Integration' Page XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35392");
  script_xref(name : "URL" , value : "http://www.kerio.com/support/security-advisories#0906");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jun/1022348.html");

  script_description(desc);
  script_summary("Check for the version of Kerio MailServer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_require_keys("KerioMailServer/Ver");
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

kerioVer = get_kb_item("KerioMailServer/Ver");
if(!kerioVer){
  exit(0);
}

# Check for 6.6.x
if(kerioVer =~ "^6\.6")
{
  # Grep for Kerio MailServer veriosn < 6.6.2.patch3
  if(version_is_less(version:kerioVer, test_version:"6.6.2.patch3")){
    security_warning(0);
  }
}
# Check for 6.7.x
else if(kerioVer =~ "^6\.7")
{
  # Grep for Kerio MailServer veriosn < 6.7.0.patch1
  if(version_is_less(version:kerioVer, test_version:"6.7.0.patch1")){
    security_warning(0);
  }
}
