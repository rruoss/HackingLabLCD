# ClamTk, copyright (C) 2004-2012 Dave M
#
# This file is part of ClamTk (http://clamtk.sourceforge.net).
#
# ClamTk is free software; you can redistribute it and/or modify it
# under the terms of either:
#
# a) the GNU General Public License as published by the Free Software
# Foundation; either version 1, or (at your option) any later version, or
#
# b) the "Artistic License".
package ClamTk::App;

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use Date::Calc 'Date_to_Days';
use File::Basename 'basename';

use POSIX 'locale_h';
use Locale::gettext;

sub get_TK_version {
    # Stick with %.2f format - 4.50 vice 4.5
    return '4.41';
}

sub get_path {
    my ( undef, $wanted ) = @_;
    my $path;

    # These are directories and files necessary for
    # preferences, storing AV signatures and more

    # First, determine home directory
    $path->{directory} = $ENV{HOME} || ( ( getpwuid $< )[-2] );

    # Default personal clamtk directory
    $path->{clamtk} = $path->{directory} . '/.clamtk';

    # For storing quarantined files
    $path->{viruses} = $path->{clamtk} . '/viruses';

    # Store history logs here
    $path->{history} = $path->{clamtk} . '/history';

    # Plain text file for preferences
    $path->{prefs} = $path->{clamtk} . '/prefs';

    # Plain text file for restoring quarantined files
    $path->{restore} = $path->{clamtk} . '/restore';

    # The db directory stores virus defs/freshclam-related stuff
    $path->{db} = $path->{clamtk} . '/db';

    # The submit directory stores file submission information
    $path->{submit} = $path->{clamtk} . '/submit';

    # Default variables
    $path->{whitelist_dir} =
        join( ';', $path->{viruses}, '/sys', '/dev', '/proc;' );

    # Most times freshclam is under /usr/bin
    $path->{freshclam} =
          ( -e '/usr/bin/freshclam' )       ? '/usr/bin/freshclam'
        : ( -e '/usr/local/bin/freshclam' ) ? '/usr/local/bin/freshclam'
        : ( -e '/opt/local/bin/freshclam' ) ? '/opt/local/bin/freshclam'
        :                                     '';

    # Use sigtool for db info
    $path->{sigtool} =
          ( -e '/usr/bin/sigtool' )       ? '/usr/bin/sigtool'
        : ( -e '/usr/local/bin/sigtool' ) ? '/usr/local/bin/sigtool'
        : ( -e '/opt/local/bin/sigtool' ) ? '/opt/local/bin/sigtool'
        :                                   '';

    # Most times clamscan is under /usr/bin
    # We'll use clampath as the actual path
    # and clamscan as clampath + scan options
    $path->{clampath} =
          ( -e '/usr/bin/clamscan' )       ? '/usr/bin/clamscan'
        : ( -e '/usr/local/bin/clamscan' ) ? '/usr/local/bin/clamscan'
        : ( -e '/opt/local/bin/clamscan' ) ? '/opt/local/bin/clamscan'
        :                                    '';

    $path->{clamscan} = $path->{clampath};

    # The default ClamAV options:
    # leave out the summary and warn on encrypted
    $path->{clamscan} .= ' --no-summary --block-encrypted ';

    return ( $wanted eq 'all' ) ? $path : $path->{$wanted};
}

sub def_paths {
    # Returns (path_of_daily.c?d, path_of_main.c?d)
    # There are 3 formats:
    # 1. The .cld files
    # 2. The .cvd files
    # 3. The {daily,main}.info directories
    # As of 4.23, we're no longer looking for the .info dirs.
    # The .cvd is the compressed database, while .cld is a
    # previous .cvd/.cld with incremental updates.
    # The problem is that you can end up with both a
    # daily.cvd AND a daily.cld, and it's a crapshoot as to
    # which one will show the most current date.  So we'll return
    # just the directory path, compare dates, and return
    # the most current date.

    my ( $DAILY_PATH, $MAIN_PATH );

    # These are the typical directories where the sigs are found.
    # Because CentOS is a little screwy, it will often contain two
    # directories of definitions... The newer one is likely in
    # /var/clamav, so check that first.  Other distros will
    # likely find the defs under /var/lib/clamav.
    my @dirs = qw(
        /var/clamav
        /var/lib/clamav
        /opt/local/share/clamav
        /usr/share/clamav
        /usr/local/share/clamav
        /var/db/clamav
        );

    # If the user selected "manual", that directory needs
    # to be checked first, so we'll jam that in with unshift.
    my $user_set      = 0;
    my $update_method = ClamTk::Prefs->get_preference('Update');
    if ( $update_method eq 'single' ) {
        $user_set = 1;
        my $paths = ClamTk::App->get_path('db');
        unshift( @dirs, $paths );
    }

    # We'll search for the daily file then main;
    # Check for daily's .cld before .cvd,
    # but main's .cvd before .cld
    my $dupe_db = ClamTk::Prefs->get_preference('DupeDB');
    for my $dir_list (@dirs) {
        # Check for duplicate daily databases
        if ( -e "$dir_list/daily.cld" && -e "$dir_list/daily.cvd" ) {
            only_one("$dir_list")
                if ( ( $dupe_db && $update_method eq 'single' )
                or ( $dupe_db && $> == 0 ) );
        }

        if ( -e "$dir_list/daily.cld" ) {
            $DAILY_PATH = $dir_list;
        } elsif ( -e "$dir_list/daily.cvd" ) {
            $DAILY_PATH = $dir_list;
        }

        # Check for duplicate main databases
        if ( -e "$dir_list/main.cld" && "$dir_list/main.cvd" ) {
            unlink("$dir_list/main.cld")
                if ( ( $dupe_db && $update_method eq 'single' )
                or ( $dupe_db && $> == 0 ) );
        }

        if ( -e "$dir_list/main.cvd" ) {
            $MAIN_PATH = "$dir_list/main.cvd";
        } elsif ( -e "$dir_list/main.cld" ) {
            $MAIN_PATH = "$dir_list/main.cld";
        }
        last if ( $DAILY_PATH && $MAIN_PATH );

        # the user may have set single - may need to update db
        last if ($user_set);
    }

    return ( $DAILY_PATH, $MAIN_PATH );
}

sub only_one {
    my ($location) = shift;
    my ( $cld, $cvd ) = ('01 Jan 1900') x 2;
    my $sigtool = get_path( undef, 'sigtool' );

    if ( open( my $CLD, '-|', "$sigtool -i $location/daily.cld" ) ) {
        while (<$CLD>) {
            if (/Build time: (\d+\s\w+\s\d{4})/) {
                $cld = $1;
                last;
            }
        }
    } else {
        # shouldn't happen
        $cld = '01 01 1970';
    }
    # warn "in only_one: cld = >$cld<\n";

    if ( open( my $CVD, '-|', "$sigtool -i $location/daily.cvd" ) ) {
        while (<$CVD>) {
            if (/Build time: (\d+\s\w+\s\d{4})/) {
                $cvd = $1;
                last;
            }
        }
    } else {
        # shouldn't happen
        $cvd = '01 01 1970';
    }
    # warn "in only_one: cvd = >$cvd<\n";

    my $cmp = comp_dates( $cld, $cvd );
    # If cmp == -1, cvd is newer.
    # If cmp ==  1, cld is newer.
    # If cmp ==  0, they're the same.
    if ( $cmp == -1 ) {
        # warn "cvd is newer\n";
        unlink("$location/daily.cld")
            or warn "Cannot delete $location/daily.cld: $!\n";
    } elsif ( $cmp == 1 ) {
        # warn "cld is newer\n";
        unlink("$location/daily.cvd")
            or warn "Cannot delete $location/daily.cvd: $!\n";
    } elsif ( $cmp == 0 ) {
        # warn "the same\n";
        unlink("$location/daily.cvd")
            or warn "Cannot delete $location/daily.cvd: $!\n";
    }
    return;
}

sub get_AV_version {
    # simple 'clamscan -V'.
    # We have to parse something like this:
    # ClamAV 0.95.3/11220/Fri Jun 18 22:06:39 2010
    # Worth keeping an eye on since it's changed in
    # past without me noticing...
    local $ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';
    delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };
    my $paths   = ClamTk::App->get_path('clampath');
    my $version = '';

    if ( open( my $c, '-|', $paths, '-V' ) ) {
        while (<$c>) {
            chomp;
            $version = $_;
        }
    }

    $version =~ s/^\S+\s+([0-9\.]+).*/$1/;
    return $version ? $version : '0.00';
}

sub get_num_sigs {
    # Adds the main + daily for total # of signatures
    my ( undef, $daily, $main ) = get_sig_info();
    return ( $daily + $main );
}

sub get_date_sigs {
    # Gets the date, preferably from daily.c?d.
    # Useful for informing user of outdated sigs.
    #my ( $date, undef, undef ) = get_sig_info( );
    my ($date) = get_sig_info('date-only');
    return $date;
}

sub get_sig_info {
    # This sub parses the signature files for the date
    # and number of signatures.
    my $date_only = shift || '';
    my ( $daily_path, $main_path ) = def_paths();

    # warn "using >$daily_path< for definitions.\n";
    # warn "I'm missing daily.{cld,cvd} and/or main.{cld,cvd}.\n"
    #    unless ( $daily_path && $main_path );

    # $INFO_DATE = Date of signatures
    # $INFO_DAILY = # of 'daily' signatures (not part of main.{cld,cvd})
    # $INFO_MAIN = # of signatures part of 'main' signatures
    my ( $INFO_DATE, $INFO_DAILY,  $INFO_MAIN )   = (0) x 3;
    my ( $MAIN_V,    $DAILY_CLD_V, $DAILY_CVD_V ) = (0) x 3;

    my $sigtool = get_path( undef, 'sigtool' );

    # example of what we need to parse
    # ClamAV-VDB:07 Nov 2009 03-23 -0500:9999:102368:44:X:X:ccordes:1257582210
    # ClamAV-VDB:14 May 2009 10-28 -0400:51:545035:42:
    # We'll store the date of main.{cld,cvd}; if daily.{cld,cvd} does not
    # exist, use that date as the date of signatures instead of returning
    # 'None found'. If daily.{cld,cvd} does exist, use that date instead.
    if ( !$date_only && $main_path ) {
        if ( open( my $main_db, '-|', "$sigtool -i $main_path" ) ) {
            while (<$main_db>) {
                chomp;
                if (/Build time:\s(\d+\s\w+\s\d{4})/i) {
                    $INFO_DATE = $1;
                }
                if (/Signatures:\s(\d+)/) {
                    $INFO_MAIN = $1;
                    #last;
                }
                if (/Verification OK/) {
                    $MAIN_V = 1;
                }
                #close($main_db)
                #    or warn "Couldn't close $main_path: $!\n";
            }
        } else {
            $INFO_MAIN = 0;
        }
    } else {
        $INFO_MAIN = 0;
    }

    my ( $cld_day, $cld_mon, $cld_year );
    my ( $cvd_day, $cvd_mon, $cvd_year );

    # Check for .cld
    if ( -e "$daily_path/daily.cld" ) {
        if ( open( my $cld_db, '-|', "$sigtool -i $daily_path/daily.cld" ) ) {
            while (<$cld_db>) {
                if (/Build time:\s(\d+\s\w+\s\d{4})/i) {
                    ( $cld_day, $cld_mon, $cld_year ) = split( /\s+/, $1 );
                }
                if (/Signatures:\s(\d+)/) {
                    $INFO_DAILY = $1;
                }
            }
            #close($cld_db)
            #    or warn "Couldn't close $daily_path (cld): $!\n";
        }
    }
    if ( !$cld_day ) {
        $cld_day  = '01';
        $cld_mon  = 'Jan';
        $cld_year = '1900';
    }

    # Check for .cvd
    if ( -e "$daily_path/daily.cvd" ) {
        if ( open( my $cvd_db, '-|', "$sigtool -i $daily_path/daily.cvd" ) ) {
            while (<$cvd_db>) {
                if (/Build time:\s(\d+\s\w+\s\d{4})/i) {
                    ( $cvd_day, $cvd_mon, $cvd_year ) = split( /\s+/, $1 );
                }
                if (/Signatures:\s(\d+)/) {
                    $INFO_DAILY = $1;
                }
            }
            #close($cvd_db)
            #    or warn "Couldn't close $daily_path (cvd): $!\n";
        }
    }
    if ( !$cvd_day ) {
        $cvd_day  = '01';
        $cvd_mon  = 'Jan';
        $cvd_year = '1900';
    }

    # If cmp == -1, cvd is newer.
    # If cmp ==  1, cld is newer.
    # If cmp ==  0, they're the same.
    my $cmp = comp_dates( "$cld_day $cld_mon $cld_year",
        "$cvd_day $cvd_mon $cvd_year" );

    my %months = (
        'Jan' => '01',
        'Feb' => '02',
        'Mar' => '03',
        'Apr' => '04',
        'May' => '05',
        'Jun' => '06',
        'Jul' => '07',
        'Aug' => '08',
        'Sep' => '09',
        'Oct' => 10,
        'Nov' => 11,
        'Dec' => 12,
        );

    $INFO_DATE =
          ( $cmp == -1 ) ? join( ' ', $cvd_day, $months{$cvd_mon}, $cvd_year )
        : ( $cmp == 0 )  ? join( ' ', $cvd_day, $months{$cvd_mon}, $cvd_year )
        : ( $cmp == 1 )  ? join( ' ', $cld_day, $months{$cld_mon}, $cld_year )
        :                  '01 01 1900';

    return ($date_only)
        ? $INFO_DATE
        : ( $INFO_DATE, $INFO_DAILY, $INFO_MAIN );
}

sub lastscan {
    my $path = ClamTk::App->get_path('history');
    my @logs = glob "$path/*.log";
    return gettext('Never') if ( !@logs );
    my %orcs;

    my @newer =
        sort { ( $orcs{$a} ||= -M $a ) <=> ( $orcs{$b} ||= -M $b ) } @logs;

    # The newest "file" (actually a string/scalar)
    # is a path like /home/foo/.clamtk/histories/01-01-Jan.log.
    # We just want the basename of that.
    my $chosen = basename( $newer[0] );

    my ( $month, $day, $year ) = split( /-/, $chosen );
    $year =~ s/(\d+)\.log/$1/;

    return "$day $month $year";
}

sub comp_dates {
    my ( $cld, $cvd ) = @_;
    my %months = (
        'Jan' => '01',
        'Feb' => '02',
        'Mar' => '03',
        'Apr' => '04',
        'May' => '05',
        'Jun' => '06',
        'Jul' => '07',
        'Aug' => '08',
        'Sep' => '09',
        'Oct' => 10,
        'Nov' => 11,
        'Dec' => 12,
        );

    my ( $cld_day, $cld_mon, $cld_year ) = split( /\s/, $cld );
    my ( $cvd_day, $cvd_mon, $cvd_year ) = split( /\s/, $cvd );

    my $cmp =
        ( Date_to_Days( $cld_year, $months{$cld_mon}, $cld_day )
            <=> Date_to_Days( $cvd_year, $months{$cvd_mon}, $cvd_day ) );

    # If cmp == -1, cvd is newer.
    # If cmp ==  1, cld is newer.
    # If cmp ==  0, they're the same.

    return $cmp;
}

sub translate {
    # This is a dummy routine, solely for the .desktop file.
    return gettext('Scan for viruses...');
}

1;
