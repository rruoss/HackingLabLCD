###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_virtualbox_priv_esc_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun VirtualBox 'VBoxNetAdpCtl' Privilege Escalation Vulnerability
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
tag_impact = "Successful exploitation will let attacker to execute arbitrary commands
  with root privileges via specially crafted arguments.
  Impact Level: Application";
tag_affected = "Sun VirtualBox version 3.x before 3.0.8";
tag_insight = "The flaw is due to the 'VBoxNetAdpCtl' configuration tool improperly
  sanitising arguments before passing them in calls to 'popen()'.";
tag_solution = "Upgrade to Sun VirtualBox version 3.0.8
  http://www.virtualbox.org/wiki/Downloads";
tag_summary = "This host is installed with Sun VirtualBox and is prone to Privilege
  Escalation vulnerability.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.901052";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3692");
  script_bugtraq_id(36604);
  script_name("Sun VirtualBox 'VBoxNetAdpCtl' Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36929");
  script_xref(name : "URL" , value : "http://www.virtualbox.org/wiki/Changelog");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2845");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-268188-1");

  script_description(desc);
  script_summary("Check for the version of Sun VirtualBox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_require_keys("Sun/VirtualBox/Lin/Ver");
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
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:sun:virtualbox", nvt:SCRIPT_OID);
if(ver =~ "^3\..*")
{
  # Grep for VirtualBox version 3.0 < 3.0.8
  if(version_is_less(version:ver, test_version:"3.0.8")){
    security_hole(0);
  }
}
