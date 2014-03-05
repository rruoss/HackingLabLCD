###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mult_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# WordPress 'wp-admin' Multiple Vulnerabilities - Aug09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers can exploit this issue by sending malicious request to several
  scripts in the wp-admin directory to gain access to administrative functions
  which may allow them to obtain sensitive information or elevate privileges.
  Impact Level: System/Application";
tag_affected = "WordPress version prior to 2.8.3 on all running platform.";
tag_insight = "- Application fails to properly sanitize user supplied input via a direct
    request to admin-footer.php, edit-category-form.php, edit-form-advanced.php,
    edit-form-comment.php, edit-link-category-form.php, edit-link-form.php,
    edit-page-form.php, and edit-tag-form.php in wp-admin/.
  - Application fails to check capabilities for certain actions, it can be
    exploited to cause unauthorized edits or additions via a direct request to
    edit-comments.php, edit-pages.php, import.php, edit-category-form.php,
    edit-link-category-form.php, edit-tag-form.php, export.php, link-add.php
    or edit.php in wp-admin/.";
tag_solution = "Update to Version 2.8.3
  http://wordpress.org/download/";
tag_summary = "The host is running WordPress and is prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900915";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2853", "CVE-2009-2854");
  script_bugtraq_id(35935);
  script_name("WordPress 'wp-admin' Multiple Vulnerabilities - Aug09");
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
  script_xref(name : "URL" , value : "http://core.trac.wordpress.org/changeset/11768");
  script_xref(name : "URL" , value : "http://core.trac.wordpress.org/changeset/11769");
  script_xref(name : "URL" , value : "http://wordpress.org/development/2009/08/wordpress-2-8-3-security-release/");

  script_description(desc);
  script_summary("Check for the version of WordPress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("host_details.inc");


# Get for WordPress Default Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

# Get KB for WordPress Version
wpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:wpPort);

if(wpVer != NULL)
{
  # Check for WordPress Version prir to 2.8.3
  if(version_is_less(version:wpVer, test_version:"2.8.3")){
    security_hole(wpPort);
  }
}
