###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_os_eol.nasl 11 2013-10-27 10:12:02Z jan $
#
# OS End Of Life Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "OS End Of Life Detection

The Operating System on the remote host has reached the end of life and should
not be used anymore";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103674";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_version ("$Revision: 11 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-05 18:11:24 +0100 (Tue, 05 Mar 2013)");
 script_name("OS End Of Life Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Determine if the os on the remote host has reached the end of life");
 script_category(ACT_END);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("os_eol.inc");
include("host_details.inc");

os_cpe = best_os_cpe();
if(!os_cpe)exit(0);

if(eol_cpes[os_cpe]) {
  message = build_eol_message(desc:desc, cpe:os_cpe);
  security_hole(port:0, data:message);
  exit();
}  

exit(0);
