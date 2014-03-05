###############################################################################
# OpenVAS Vulnerability Test
#
# Show System Characteristics
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Show OVAL System Characteristics if they have been previously gathered and are available in the Knowledge Base.";

if (description)
{
 script_id (103999);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-08 16:17:59 +0100 (Tue, 08 Mar 2011)");

 script_name ("Show System Characteristics");

 desc = "
 Summary:
 " + tag_summary;

 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag (name:"risk_factor", value:"None");
 script_description (desc);
 script_summary ("Show System Characteristics");
 script_category (ACT_END);
 script_family ("General");
 script_copyright ("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies ("kb_2_sc.nasl", "gb_nist_win_oval_sys_char_generator.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit (0);
}

if (get_kb_item("SMB/WindowsVersion")) {
  sc = get_kb_item ("nist_windows_system_characteristics");
} else {
  sc = get_kb_item ("system_characteristics");
}

if (sc)
{
  log_message (data: sc, proto: "OVAL-SC");
}

exit (0);

