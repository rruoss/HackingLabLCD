# OpenVAS Vulnerability Test
# $Id$
# Description: Helper functions for SSH-based target host access
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 9 $

# XXX: the version tests should be eventually consolidated with
# the methods from revisions-lib.inc.


function find_bin(prog_name, sock) {
  
  local_var r, whe, whi, cl;
  
  whe = "";
  whi = "";

  if(! sock) {
    sock = ssh_login_or_reuse_connection();
  }
  if(sock) {

    cl = check_locate(sock:sock);

    if ( cl ) {
        r = split(ssh_cmd(socket:sock, cmd:"locate -ei *bin/"+prog_name, timeout:60));
    } else {
        r = NULL;
    }

  } else {
     r = NULL;
  }

  if( "bin/"+prog_name >!< r ) {
    if(sock) {
        whe = ssh_cmd(socket:sock, cmd:"whereis -b "+prog_name, timeout:60);
        if( "bin/"+prog_name >< whe ) {
           r = split(substr(whe - (prog_name + ":"), 1), sep:" ");
        } else {
           r = NULL;
        }
     }
  }

  if(isnull(r) ) {
    if(sock) {
        whi = ssh_cmd(socket:sock, cmd:"which -a "+prog_name, timeout:60);
        if(("which: no "+prog_name) >!< whi) {
           r = split(whi);
        } else {
           r = NULL;
        }
    }
  }

  return (r);

}

function find_file(file_name, file_path, useregex, regexpar, sock ) {

  local_var r, f, fname, lparam, cl;

  r = NULL;

  if( useregex ) {
    lparam = "-eir";
  } else {
    lparam = "-ei";
  }

  use_find = get_kb_item("Enable/find");
  descend_directories = get_kb_item("Descend/OFS");

  if(isnull(use_find))use_find="yes";
  if(isnull(descend_directories))descend_directories="yes";   

  fname = ereg_replace(pattern:"\*.+", string:file_name, replace:"");

  if(! sock) {
    sock = ssh_login_or_reuse_connection();
  }
  if(sock) {

    cl = check_locate(sock:sock);

    if ( cl ) {
        r = split(ssh_cmd(socket:sock, cmd:"locate "+lparam+" "+raw_string(0x22)+file_path+file_name+regexpar+raw_string(0x22), timeout:60));
    } else {
        r = NULL;
    }

    if(fname >!< r && ("yes" >< use_find) ) { 
      if(!isnull(file_path) ) {

        cmd =  "find "+raw_string(0x22)+file_path+raw_string(0x22);

        if("no" >< descend_directories) {
          cmd += " -xdev";
        }

        cmd += " -maxdepth 7 -mindepth 1";
        cmd += ' \\( -path "*/proc" -o -path "/dev" -o -path "/sys" -o -path "/media" -o -path "/tmp" -o -path "/var" \\) -prune -o ';
        cmd += " -name "+raw_string(0x22);
        cmd += file_name+raw_string(0x22)+" -a \( -type f -o -type l \) -print 2>/dev/null";

        f = split(ssh_cmd(socket:sock, cmd: cmd, timeout:60));

      }
    }
  }

  if( fname >!< r ) {
    if( fname >< f && "No such file or directory" >!< f) {
      r = f;
    } else {
      r = NULL;
    }
  }
  return (r);
}

function get_bin_version(full_prog_name, version_argv, ver_pattern, sock) {
  local_var loc_version, r, report;

  full_prog_name = chomp(full_prog_name);
  version_argv = chomp(version_argv);

  if(! sock) {
    sock = ssh_login_or_reuse_connection();
  }
  if(sock) {
    r = ssh_cmd(socket:sock, cmd:full_prog_name +" "+version_argv, timeout:60);
  }
  loc_version = eregmatch(pattern:ver_pattern, string:r);
  if(loc_version != NULL) loc_version[max_index(loc_version)] = r;
  return (loc_version);
}

function get_string_version(text, ver_pattern) {
  local_var loc_version;

  if( isnull( ver_pattern) ) {           # Standard Version Pattern for most cases
    ver_pattern = "([0-9\.]+)";
  }
  loc_version = eregmatch(pattern:ver_pattern, string:text);
  if(loc_version != NULL) loc_version[max_index(loc_version)] = text;
  return (loc_version);
}

function version_is_less(version ,test_version, icase) {
  return (version_test(version:version, test_version:test_version, less:TRUE, icase:icase));
}

function version_is_equal(version, test_version, icase) {
  return (version_test(version:version, test_version:test_version, less:FALSE, icase:icase));
}

function version_test(version, test_version, less, icase) {
  local_var ver_ary, test_ary, ver_num, ver_sep, i, r, s, char_found;

  if(isnull(version) || version == "" || version == 0 || version == '0' || version == "unknown") return FALSE;

  if(isnull(icase) ) icase = TRUE;
  if(icase) {
    version = tolower(version);
    test_version = tolower(test_version);
  }
  ver_sep = ereg_replace(pattern:"([A-Za-z0-9])", string: version, replace:"");
  if( ver_sep == "" ) ver_sep = ".";   # Set Standard Separator
  ver_ary = split(version, sep:ver_sep[0], keep:0);
  ver_sep = ereg_replace(pattern:"([A-Za-z0-9])", string: test_version, replace:"");
  if( ver_sep == "" ) ver_sep = ".";   # Set Standard Separator
  test_ary = split(test_version, sep:ver_sep[0], keep:0);
  while(max_index(ver_ary) < max_index(test_ary) ) {
    ver_ary[max_index(ver_ary)] = "0";
  }
  while(max_index(ver_ary) > max_index(test_ary) ) {
    test_ary[max_index(test_ary)] = "0";
  }
  foreach i (keys(test_ary) ) {
    r = eregmatch(pattern:"([0-9]+)", string:test_ary[i]);
    s = eregmatch(pattern:"([A-Za-z])", string:test_ary[i]);
    test_rc = eregmatch(pattern:"rc([0-9]+)", string:test_ary[i]);
    if(isnull(s) ) {
      test_ary[i] = int(r[0]) * 128;                         # Changed to * 128 so if a char follows a number the number is more significant 
      char_found = FALSE;
    } else {
      if(isnull(test_rc)) {
        test_ary[i] = (int(r[0]) * 128) + ord(s[0]);
      } else {
        test_ary[i] = test_rc[1];
      }
      char_found = TRUE;
    }
    r = eregmatch(pattern:"([0-9]+)", string:ver_ary[i]);
    s = eregmatch(pattern:"([A-Za-z])", string:ver_ary[i]);
    ver_rc = eregmatch(pattern:"rc([0-9]+)", string:ver_ary[i]);
    if(isnull(s) ) {
      ver_ary[i] = int(r[0]) * 128;
    } else if(char_found) {
             if(isnull(ver_rc)) {
               ver_ary[i] = (int(r[0]) * 128) + ord(s[0]);
	     } else {
                ver_ary[i] = ver_rc[1];
	     }
           } else {
             if(isnull(r) ) {
               ver_ary[i] = ord(s[0]);
             } else {
               if(! less) return (0);			     # If char found in test_version and no char in version it is not equal
	       ver_ary[i] = int(r[0]) * 128;                 # No chars if test_version has no chars on this position else 1.1.1a is > 1.1.2
             }
    }

    if(less) {

      if(ver_ary[i] < test_ary[i]) return (1);
      if(ver_ary[i] > test_ary[i]) return (0);
    } else {
      if(ver_ary[i] != test_ary[i]) return (0);
    }
  }
  if(less) return (0); else return (1);
}

function version_is_less_equal(version, test_version) {
  if(version_is_equal(version:version, test_version:test_version) ) return (1);
  if(version_is_less(version:version, test_version:test_version) ) return (1);
  return (0);
}

function version_is_greater_equal(version, test_version) {
  if(version_is_equal(version:version, test_version:test_version) ) return (1);
  if(version_is_less(version:test_version, test_version:version) ) return (1);
  return (0);
}

function version_is_greater(version, test_version) {
  if(version_is_less(version:test_version, test_version:version) ) return (1);
  return (0);
}

function version_in_range(version, test_version, test_version2){
  if(version_is_greater_equal(version:version, test_version:test_version)){
    if(version_is_less_equal(version:version, test_version:test_version2)) return (1);
  }
  return (0);
}

function get_version_from_kb(port,app) {

  local_var port, app, vers, version, matches;

  if(isnull(port) || isnull(app))return FALSE;
  
  if(!version = get_kb_item(string("www/", port, "/",app)))return FALSE;
  if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))return FALSE;
  
  vers = matches[1];

  if(isnull(vers) || vers == "unknown") return FALSE;

  return string(vers); 

} 

function get_dir_from_kb(port,app) {

  local_var port, app, dir, version, matches;

  if(isnull(port) || isnull(app))return FALSE;
  
  if(!version = get_kb_item(string("www/", port, "/",app)))return FALSE;
  if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))return FALSE;

  dir = matches[2];

  if(isnull(dir)) return FALSE;

  return string(dir); 

}

function get_samba_version() { # add  "script_dependencies("smb_nativelanman.nasl");" to your NVT to make this function work


  if(!lanman = get_kb_item("SMB/NativeLanManager"))return FALSE;
  if("Samba" >!< lanman)return FALSE;

  if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string: lanman))return FALSE;
  if(isnull(version[1]))return FALSE;

  return version[1];

} 

function check_locate(sock) {

    local_var locate_tested, r;

    if( get_kb_item("lsc/locate/broken") ) return FALSE;

    if( ! get_kb_item("lsc/locate/tested") ) {

        r = ssh_cmd(socket:sock, cmd:"locate -S", timeout:60);

        if( ("Database /"     >!< r       ||
             (  "bytes"       >!< r       && 
                "Compression" >!< r       && 
                "Filenames"   >!< r       &&
                "file names"  >!< r ) )   || 
              "command not found" >< r    ||
              "locate:"       >< r         
              ) { 

          set_kb_item(name: "lsc/locate/broken", value: TRUE); 
          set_kb_item(name: "lsc/locate/tested", value: TRUE);
          return FALSE;

        }
     
        set_kb_item(name: "lsc/locate/tested", value: TRUE);
    }    

    return TRUE;
}

## This function will return the version of the given file
function fetch_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}


