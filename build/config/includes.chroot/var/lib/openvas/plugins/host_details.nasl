###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Centralized and organized host informations base
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This scripts aggregates the OS detection information gathered by several
NVTs and store it in a structured and unified way";


if(description) {
  script_id(103997);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-16 12:21:12 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Host Details");

desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Gather and centralize details about the current target");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_category(ACT_END);
  script_dependencies("cpe_inventory.nasl");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("host_details.inc");

# -- Script entry point --
display_report = get_preference("report_host_details");
if (display_report && "yes" >< display_report) {
  report_host_details();
}

