###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_version.nasl 41 2013-11-04 19:00:12Z jan $
#
# Detection of MySQL/MariaDB
#
# Authors:
# Michael Meyer
#
# Updated By : Thanga Prakash S <tprakash@secpod.com> on 2013-07-31
# Updated acording to cr57 and to detect higher versions
#
# Updated By : Thanga Prakash S <tprakash@secpod.com> on 2013-07-31
# Updated check report_paranoia and to set cpe "cpe:/a:oracle:mysql"
# for versions released after MySQL owned by Oracle.
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100152";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 41 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"detection", value:"remote probe");
  script_name("MySQL/MariaDB Detection");

  tag_summary =
"Detection of installed version of MySQL/MariaDB.

Detect a running MySQL/MariaDB by getting the banner, Extract the version
from the banner and store the information in KB";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Check for MySQL/MariaDB");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("byte_func.inc");
include("version_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

if(!get_port_state(port))exit(0);

version = 'unknown';

if(!version=get_mysql_version(port))
{ # I found no Plugin that ever set mysql_version ("mysql/version/"). But perhaps i missed somthing, so i check first if version is set.

  soc = open_sock_tcp (port);
  if (!soc)exit (0);

  buf = recv(socket:soc, length:4);
  if(!buf)exit(0);

  # http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol

  plen = ord(buf[0]) + (ord(buf[1])/8) + (ord(buf[2])/16); # Packet Length
  if(ord(buf[3]) != 0)exit(0); # The first packet of a client query will have Packet Number = 0

  buf = recv (socket:soc, length:plen);
  if(strlen(buf) != plen)exit(0);

  if(ord(buf[0]) == 255)
  { # connect not allowed

    errno = ord(buf[2]) << 8 | ord(buf[1]);

    if(errno == 1129 || errno == 1130)
    {
      set_kb_item(name:"MySQL/blocked", value:TRUE);

      if(errno == 1129) {
        log_message(port:port, data:"Scanner received a ER_HOST_IS_BLOCKED"+
                       " error from the remote MySQL/MariaDB server.\nSome"+
                         " tests may fail. Run 'mysqladmin flush-hosts' to"+
                                    "enable scanner access to this host.\n");
      }
      else if(errno == 1130) {
        log_message(port:port, data:"Scanner received a ER_HOST_NOT_PRIVILEGED"+
                           " error from the remote MySQL/MariaDB server.\nSome"+
                             " tests may fail. Allow the scanner to access the"+
                                     " remote MySQL server for better results.");
      }

      #MySQL_FOUND = TRUE;
      exit(0);  # If the port is blocked, we can't find the server whether it is MySQL/MariaDB.
    }
  }

  else if(ord(buf[0]) == 10)
  { #  connect allowed
    if("MariaDB" >< buf){
      MariaDB_FOUND = TRUE;
    }
    else{
      MySQL_FOUND = TRUE;
    }
    for (i=1; i<strlen(buf); i++)
    {
      if (ord(buf[i]) != 0) { # server_version is a Null-Terminated String
        version += buf[i];
      } else{
            break;
      }
    }
  }
} else {
   MySQL_FOUND = TRUE;
   getVERSION = TRUE;
}

if(MySQL_FOUND)
{
  if(version) {
    if(!getVERSION) {
     set_mysql_version(port:port, version:version);
    }
  } else {
     version = 'unknown';
  }

  set_kb_item(name:"MySQL/installed",value:TRUE);

  # run depending nvts only if report_paranoia is > 1 to avoid false positives against backports
  if (report_paranoia > 1 ) {
    set_kb_item(name:'MySQL/paranoia', value:TRUE);
  }

  register_service(port:port, proto:"mysql");

  if(version_is_less_equal(version:version, test_version:"5.0.96") ||
     version_in_range(version:version, test_version:"5.1", test_version2:"5.1.50") ||
     version_in_range(version:version, test_version:"5.5", test_version2:"5.5.9"))
  {
    cpe = build_cpe(value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mysql:mysql:");
    if(isnull(cpe))
      cpe = 'cpe:/a:mysql:mysql';
  }
  else
  {
    cpe = build_cpe(value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:oracle:mysql:");
    if(isnull(cpe))
      cpe = 'cpe:/a:oracle:mysql';
  }

  register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"MySQL", version:version, install:port + '/tcp', cpe:cpe, concluded: buf),
              port:port);

}


if(MariaDB_FOUND)  # If MariaDB is found in the port, Set the version for MariaDB
{
  if(version) {
    set_mariadb_version(port:port, version:version);
  } else {
     version = 'unknown';
  }

  set_kb_item(name:"MariaDB/installed",value:TRUE);

  # run depending nvts only if report_paranoia is > 1 to avoid false positives against backports
  if (report_paranoia > 1 ) {
    set_kb_item(name:'MariaDB/paranoia', value:TRUE);
  }

  register_service(port:port, proto:"mariadb");

  cpe = build_cpe(value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mariadb:mariadb:");
  if(isnull(cpe))
    cpe = 'cpe:/a:mariadb:mariadb';

  register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"MariaDB", version:version, install:port + '/tcp', cpe:cpe, concluded: buf),
              port:port);

}

exit(0);
