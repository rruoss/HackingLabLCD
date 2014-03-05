###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums_win_ok.nasl 67 2013-11-18 08:50:51Z mwiegand $
#
# List Windows File with no checksum violation or error
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.96181";

tag_summary = "List Windows files with no checksum violation or error";

if (description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 67 $");

  script_name("Windows file Checksums: Matches");

  desc = "Summary:
" + tag_summary;

  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-18 09:50:51 +0100 (Mon, 18 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-09-09 11:07:49 +0200 (Mon, 09 Sep 2013)");
  script_description(desc);
  script_summary("List Windows file Checksum Matches");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("policy_file_checksums_win.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

md5pass = get_kb_item("policy/win_md5cksum_ok");
sha1pass = get_kb_item("policy/win_sha1cksum_ok");

if (md5pass || sha1pass) {
  report = 'The following file checksums match:\n\n';
  report += 'Filename|Result|Errorcode;\n' + md5pass + sha1pass;
  log_message(data:report, port:0, proto:"ssh");
}

exit(0); 