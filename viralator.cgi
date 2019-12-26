#!/usr/bin/perl -T
# Author Info:    viralator@loddington.com Copyright 2001 Duncan Hall
# changes from 0.8->0.9 Open IT S.r.l. (http://www.openit.it):
#  - Diaolin (diaolin@diaolin.com)
#  - Marco Ciampa (ciampix@libero.it)
# Changes from 0.9pre2.1:
#  - Alceu Rodrigues de Freitas Junior (glasswalk3r@yahoo.com.br)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# :TODO:24/01/2006:ARFJr: Include parameter for maximum download size for scanning
# :TODO:24/01/2006:ARFJr: Create better HTML header (lang, encoding and XML declaration)
# :TODO:24/01/2006:ARFJr: Allow Viralator browser to use Squid cache
# :TODO:12/12/2005:ARFJr: create a Javascript control do avoid two download requests in the same window
# :TODO:09/01/2006:ARFJr: create a Perl module to define constants
use warnings;
use strict;

###################
# Perl imported modules
use CGI 3.15;
use LWP 5.66;
use URI::Split qw (uri_split);
use URI::Escape;
use sigtrap 'handler' => \&terminated, 'normal-signals';
use Digest::MD5 qw(md5_base64);
use IPC::Open3;
use POSIX qw( sys_wait_h );

###################
# constants
use constant VERSION_NUMBER => '0.9.7';
use constant VERSION_TITLE  => 'Viralator - version ';
use constant SITE           => 'http://viralator.sourceforge.net';
use constant BGCOLOR        => '#FFFFFF';
use constant CONFIG_FILE    => '/etc/viralator/viralator.conf';
use constant LANG_DIR       => '/etc/viralator/languages';

# used to validate URL passed as parameters to the CGI
use constant URL_REGEX => '\%\w\.\-\_\?\~\+\:\/\s\(\)';

# used to validate filenames passed as parameters to the CGI
use constant FILE_REGEX => '\w\-\_\.\s\%\(\)';

# used to validate directories (UNIX style) passed as parameters to the CGI
use constant UNIX_DIR_REGEX => '\w\-\_\.\/';

{
    no warnings;
    $CGI::HEADER_ONCE     = 1;
    $CGI::POST_MAX        = 1024 * 100;
    $CGI::DISABLE_UPLOADS = 1;

}

##################
# CONFIGURATION
##################

open( CONFIG, '<' . CONFIG_FILE )
    or die( 'Cannot read ' . CONFIG_FILE . ': ' . $! );

my @temp;
my %config;

while (<CONFIG>) {

    #jumping no interesting lines
    next if $_ =~ /#/;
    chomp;
    next unless ( $_ =~ /\-\>/ );
    @temp = split( /\-\>/, $_ );

    #removes spaces at the begging and at the end of each string
    foreach (@temp) {

        s/^\s+//;
        s/\s+$//;

    }

    $temp[1] = 'X' unless ( defined( $temp[1] ) );
    $config{ $temp[0] } = $temp[1];
    @temp = ();

}

close(CONFIG);

# checking the values

my @test = qw(
    default_language
    scannerpath
    virusscanner
    viruscmd
    alert
    secret
    downloads
    downloadsdir
    scannersummary
    popupfast
    popupback
    popupwidth
    popupheight
    filechmod
    css_file
    dirmask
    skip_downloads
    progress_unit
    progress_indicator);

foreach (@test) {

    die( 'No directive ' . $_ . ' declared in ' . CONFIG_FILE )
        unless ( exists $config{$_} );
    die( 'No value on ' . $_ . 'in ' . CONFIG_FILE )
        if ( $config{$_} eq 'X' );

}

undef(@test);

#reading language file

open( LANG, '<' . LANG_DIR . '/' . $config{default_language} )
    or die 'Cannot read the default language file '
    . $config{default_language} . ' at '
    . LANG_DIR;

my %lang;

while (<LANG>) {

    #jumping no interesting lines
    next if $_ =~ /#/;
    chomp;
    next unless ( $_ =~ /=/ );

    # cleaning up values
    $_ =~ s/\s+=\s+/=/;
    @temp = split( /=/, $_ );
    $temp[1] = 'X' unless ( defined( $temp[1] ) );
    $lang{ $temp[0] } = $temp[1];
    @temp = ();

}

undef(@temp);

#######################
# START OF THE PROGRAM
#######################

# :WARNING:24/01/2006:ARFJr: Terrible design... this object is global
my $viralator = new CGI;

#testing the download repository
test_repository( $config{downloads} );

# :WARNING:02/02/2006:ARFJr: the method script_name is giving back the parameter of the CGI
# looks like a bug for me in CGI.pm
#my $scriptname = $viralator->script_name();
my $scriptname = ( uri_split( $viralator->url() ) )[2];

#The address of the server this script lives on can be user defined
my $servername;
$config{servername} ? $servername = $config{servername} : $servername =
    $viralator->server_name();

#The user IP address connected to the proxy
my $client = $viralator->remote_addr();

# date and ugly date functions rewritten to fix some tainting problems
my $date = scalar localtime;

#a really big number for our popup!
my $uglydate = time;

# the sum of data length read by LWP file fetcher
my $datasum = 0;

# how much data a "bar" represents
$config{progress_unit} =
      '<img src="http://'
    . $servername . '/'
    . $config{progress_unit}
    . '" width="4" height="22">';
$config{progress_indicator} =
      '<img src="http://'
    . $servername . '/'
    . $config{progress_indicator}
    . '" width="200" height="22">';

my $bar_value = 0;
my $count_bar = 0;

my $requestpage = $viralator->referer;

# Defining HTTP header
# It should always tells to the browser that the page is already expired (no caching)
# Should defined charset at the HTTP header (and it will be defined latter at the HTML header too)
unless ( defined( $config{charset} ) ) {

    print $viralator->header( -expires => 'now' );

} else {

    print $viralator->header( -expires => 'now',
                              -charset => $config{charset} );

}

# If we do not go any parameter, this means problems! Probably
# the redirector program is not configurated correctly:
# Viralator should receive at least the "url" parameter

unless ( $viralator->param() ) {

    error( 'error', $lang{noparam},
           'No paramaters received. Please check your redirection program.' );

    # at least one, we're fine
} else {

    # very first call, from the redirector
    unless ( $viralator->param('action') ) {

        my $url = $viralator->param('url');
        test_param( 'url', $url );

        # check if we should pop the download window as soon as we are called

        if ( $config{popupfast} eq 'true' ) {

            print html_start( { onload => 'WinOpen()' } );

        } else {

            print html_start();

        }

        print $viralator->h3( $lang{presentation} ),
            $viralator->p(
                           $lang{startclick}
                               . $viralator->submit(
                                                     -value   => $lang{start},
                                                     -onClick => 'WinOpen()'
                               )
            );

        # Since there is no REFERER to go back, try to use Javascript to go back
        unless ( defined($requestpage) and ( $requestpage ne '' ) ) {

            print $viralator->p(
                                 $lang{mainpage},
                                 $viralator->submit(
                                                     -value   => $lang{here},
                                                     -onclick => '"history.go(-1);"'
                                 )
            );

        } else {

            # extracting only the main url from referer information
            my @main_page = uri_split($requestpage);

            print $viralator->p( $lang{meanwhile} ), $viralator->start_ul(),
                $viralator->li( $lang{requestpage},
                                $viralator->a( { -href => $requestpage }, $lang{here} ), '.' ),
                $viralator->li(
                                $lang{mainpage},
                                $viralator->a(
                                               { -href => "$main_page[0]://$main_page[1]" },
                                               $lang{here}
                                ),
                                '.'
                );
            $viralator->end_ul();

        }

        # Fake sites
        #
        # on many sites it can be found an ugly problem due to the fake URL passed
        # from remote sites, the result is a strange \ .............
        # If you know anything about this sites and you want to permit your users
        # downloading anyway, you can put a abortregexi into squirm.patterns like this
        # this example is a site that has convinced us to write this workaround
        # www.powerarchiver.com
        #
        # abortregexi (^http://www\.powerachiver\.com/.*)
        #
        # in this case all your users can download from powerarchiver without virus
        # scanning :-(

        if ( ( $url =~ /\s*\?\s*/ ) or ( $url =~ /\s*\\\s*/ ) ) {

            WinOpen(
                     'http://' . $servername . $scriptname . '?action=errpop',
                     $uglydate,
                     'width='
                         . $config{popupwidth}
                         . ',height='
                         . $config{popupheight}
                         . ',scrollbars=1,resize=no'
            );

        } else {

            # Lets start by returning the user to the page they found the file on and
            # launching a pop up window
            # The pop up windows should have some useful info in it about what is going on.

            WinOpen(
                     'http://' . $servername . $scriptname . '?action=popup&fileurl=' . $url,
                     $uglydate,
                     'width='
                         . $config{popupwidth}
                         . ',height='
                         . $config{popupheight}
                         . ',scrollbars=1,resize=no'
            );
        }

        print $viralator->end_html;

        # ACTION !
        # ok, we got action call and maybe more parameters

    } else {

        my $action = $viralator->param('action');
        test_param( 'action', "$action" );

        # error in the file request
        if ( $action eq 'errpop' ) {

            print html_start();
            print $viralator->start_center, $viralator->h1( $lang{dinerr} ),
                $viralator->p( $lang{urlerr} ), $viralator->p( $lang{admincall} ),
                $viralator->start_form,
                $viralator->submit(
                                    -value   => $lang{wclosew},
                                    -onClick => 'window.close()'
                ),
                $viralator->endform, $viralator->end_center, $viralator->end_html;

            # Step 2
            # downloading the file
        } elsif ( $action eq 'popup' ) {

            my $fileurl = $viralator->param('fileurl');
            my $result;
            my $username;
            my $password;
            my $temp_dir;

            # fileurl should be tested as well against taint values
            $fileurl = clean_taint( $fileurl, @{ [URL_REGEX] } );

            my $filename = parse_fileurl($fileurl);

            $| = 1;

            # giving more information to the user in the window name

            print html_start(
                              {
                                title  => "$lang{downloading} $fileurl",
                                onload => 'clearInterval(intervalID1);'
                              }
            );

            # check if we should make the browser goes back when the download window opens

            set_javascript( ( $config{popupback} eq 'true' ? 'opener.history.go(-1);' : '' ) );

            # no temp_dir param means that this is the first call of popup
            unless ( defined( $viralator->param('temp_dir') ) ) {

                $client = clean_taint( $client, '\d\.' );
                $config{downloads} = clean_taint( $config{downloads}, @{ [UNIX_DIR_REGEX] } );

                # generating an randomic directory named based on client IP address
                $temp_dir = $client . rand(time);

                $config{dirmask} = clean_taint( $config{dirmask}, '\d' );
                $config{dirmask} = oct( $config{dirmask} );
                umask( $config{dirmask} );

                mkdir("$config{downloads}/$temp_dir")
                    or error( 'error', $lang{download_error},
                              "Error when trying to create $config{downloads}/$temp_dir: $!",
                              'noheader' );

                $result =
                    get_file( $username, $password, $fileurl, $filename, $temp_dir,
                              md5_base64( $filename, $config{secret}, $temp_dir ) );

                # means a second call by get_file
            } else {

                $temp_dir = $viralator->param('temp_dir');
                $temp_dir = clean_taint( $temp_dir, @{ [UNIX_DIR_REGEX] } );

                $username = $viralator->param('username')
                    if ( $viralator->param('username') );
                $password = $viralator->param('password')
                    if ( $viralator->param('password') );

                my $digest = $viralator->param('digest');
                error2(
                        [
                          'warning', $lang{md5_error},
                          'Received corrupted data when trying to stop a download',
                          'noheader', $config{downloads}, $temp_dir, $filename
                        ]
                    )
                    unless (
                            compare_digests( $digest, $filename, $config{secret}, $temp_dir ) );

                $result =
                    get_file( $username, $password, $fileurl, $filename, $temp_dir, $digest );

            }

        CHECKIT: {

                if ( $result == 0 ) {

                    print $viralator->p( $lang{download_error} ), $viralator->start_center(),
                        $viralator->submit(
                                            -value   => $lang{wclosew},
                                            -onClick => 'window.close()'
                        ),
                        $viralator->end_center(), $viralator->end_html;

                    last CHECKIT;

                }

                if ( $result == 2 ) {

                    print $viralator->end_html;
                    last CHECKIT;

                }

                if ( $result == 1 ) {

                    # calling the antivirus program
                    cleanit( $fileurl, $filename, $temp_dir );

                    # If $filename exists in the download dir then it is clean or has been
                    # cleaned (depending on your scanner options),if not then the virus scanner
                    # has renamed or deleted the file (depending on your scanner options) and
                    # it is infected

                    # We check to see if the filename is greater than 1 character long

                    my $filenamesize = length($filename);

                    if (    ( -e "$config{downloads}/$temp_dir/$filename" )
                         && ( $filenamesize > 1 ) )
                    {

                        # :WARNING:09/01/2006:ARFJr: Changing the code below to module URI::Escape function uri_escape()
                        # Check $filename for spaces or odd charaxters

                        my $original_filename = uri_unescape($filename);

                        print $viralator->p("$lang{oktodown}");

                        print <<BLOCK;
<META HTTP-EQUIV="Refresh" CONTENT="1; URL=$config{downloadsdir}/$temp_dir/$filename">
<strong>$lang{oncedown}</strong>
BLOCK

                        #changing the value of the parameter 'action'
                        $viralator->param( -name  => 'action',
                                           -value => 'delete' );

                        # Form to close download window and delete the downloaded file
                        print $viralator->start_form(
                                          -method => 'post',
                                          -action => 'http://' . $servername . '/' . $scriptname
                            ),
                            $viralator->hidden(
                                                -name    => 'action',
                                                -default => 'delete'
                            ),

                            $viralator->hidden(
                                                -name    => 'filename',
                                                -default => $original_filename
                            ),

                            $viralator->hidden(
                                                -name    => 'temp_dir',
                                                -default => $temp_dir
                            ),

                            $viralator->hidden(
                                -name    => 'digest',
                                -default =>
                                    md5_base64( $original_filename, $config{secret}, $temp_dir )
                            ),

                            $viralator->p( { -align => 'center' },
                                           $viralator->submit( -name => $lang{wclosew} ) ),
                            $viralator->end_form, window_scrolldown();

                    } else {

                        print $viralator->h2( $lang{vfounddl} );

                        error(
                               'warning',
                               $lang{fileremoved},
                               "Problem with request made by $client: file does not exists or is too short."
                        );

                    }

                    print $viralator->end_html;
                    last CHECKIT;

                    # end of $result = 1
                }

                # end of CHECKIT block
            }

            # Kill process downloading file, delete file and close window

        } elsif ( $action eq 'delete' ) {

            my $filename = $viralator->param('filename');
            my $digest   = $viralator->param('digest');
            my $temp_dir = $viralator->param('temp_dir');

            error( 'warning', $lang{md5_error},
                   'Received corrupted data when trying to stop a download', 'noheader' )
                unless ( compare_digests( $digest, $filename, $config{secret}, $temp_dir ) );

            $filename          = clean_taint( $filename,          @{ [FILE_REGEX] } );
            $config{downloads} = clean_taint( $config{downloads}, @{ [UNIX_DIR_REGEX] } );
            $temp_dir          = clean_taint( $temp_dir,          @{ [UNIX_DIR_REGEX] } );

            print html_start( { onload => 'window.setTimeout("window.close()","2000");' } );

            print $viralator->br(), "$lang{wremoving} $filename $lang{wfromsrv}... ";

            rm_download( "$config{downloads}/$temp_dir", $filename );

            print $lang{done}, $viralator->end_html;

            # this will cancel a download request
            # it will kill the process running the download, erase the downloaded file
            # and close the user window

        } elsif ( $action eq 'StopMe' ) {

            my $filename  = $viralator->param('filename');
            my $processid = $viralator->param('processid');
            my $digest    = $viralator->param('digest');
            my $temp_dir  = $viralator->param('temp_dir');

            error( 'warning', $lang{md5_error},
                   'Received corrupted data when trying to stop a download' )
                unless (
                compare_digests( $digest, $filename, $processid, $config{secret}, $temp_dir ) );

            print html_start( { onload => 'window.setTimeout("window.close()","2000");' } );

            print $viralator->p( $lang{downabort} );

            print $viralator->p( $lang{kill} );
            $processid = clean_taint( $processid, '\d+' );
            kill 'TERM', $processid;

            print $viralator->p("$lang{wremoving} $filename $lang{wfromsrv}");

            $config{downloads} = clean_taint( $config{downloads}, @{ [UNIX_DIR_REGEX] } );
            $filename          = clean_taint( $filename,          @{ [FILE_REGEX] } );
            $temp_dir          = clean_taint( $temp_dir,          @{ [UNIX_DIR_REGEX] } );
            rm_download( "$config{downloads}/$temp_dir", $filename );

            print $viralator->end_html;

            # not defined value for action, shows error

        } else {

            error( 'error', $lang{no_resource}, "Invalid value for action parameter: $action" );

        }

    }

}

############################
##### FUNCTION AREA ########
############################

# Hands errors gracefully
# :TODO:26/01/2006:ARFJr: Should avoid using CGI.pm objects and other
# variables that may be not initialized when the error occurs?
sub error {

    # message type: warning or error
    my $type = shift;

    # title of the page
    my $title;

    if ( $type eq 'warning' ) {

        $title = $lang{warning};

    } else {

        $title = $lang{error};

    }

    # this one goes to the browser
    my $message = shift;

    # this one goes to the log file
    my $to_log = shift;

    #decides if prints the start_html
    my $flag = shift;

    unless ( defined($flag) ) {

        print html_start();

    }

    print $viralator->h1($title), $viralator->p($message), $viralator->p( $lang{admincall} ),
        $viralator->start_center(),
        $viralator->submit(
                            -value   => $lang{wclosew},
                            -onClick => 'window.close()'
        ),
        $viralator->end_center(), window_scrolldown();

    print $viralator->end_html;

    if ( defined($client) ) {

        die "$to_log - requested by $client";

    } else {

        die "$to_log";

    }

}

# download the file
# A good part of this function code was gently given by Oleg Y. Ivanov <g16@mail.ru>

sub get_file {

    my $username = shift;
    my $password = shift;
    my $fileurl  = shift;
    my $filename = shift;
    my $temp_dir = shift;
    my $digest   = shift;

    delete @ENV{qw(IFS CDPATH ENV BASH_ENV PATH)};

    # setting an invalid pathname
    $ENV{PATH} = '/dev/null';

    $config{downloads} = clean_taint( $config{downloads}, @{ [UNIX_DIR_REGEX] } );

    $fileurl  = clean_taint( $fileurl,  @{ [URL_REGEX] } );
    $filename = clean_taint( $filename, @{ [FILE_REGEX] } );
    $temp_dir = clean_taint( $temp_dir, @{ [FILE_REGEX] } );

    my $fetcher = LWP::UserAgent->new;

    # defining a cool name for the "browser"
    $fetcher->agent( VERSION_TITLE . VERSION_NUMBER );
    $fetcher->protocols_allowed( [qw(http https ftp)] );

    #first, checking if the filename exists on the server and getting more information about it
    my $response = $fetcher->head($fileurl);

    if ( $response->header('WWW-Authenticate') ) {

        unless ( defined($username) ) {

            my $realm_name = $response->header('WWW-Authenticate');
            my $pos = index( $realm_name, '"' );
            $realm_name = substr( $realm_name, $pos + 1, index( $realm_name, '"', $pos + 1 ) );
            $realm_name =~ s/^\"//;
            $realm_name =~ s/\"$//;

            print $viralator->h3("$lang{authrequired} \"$realm_name\""),
                $viralator->p("$lang{pleaseuserpass} $fileurl"),
                $viralator->start_form(
                                        -method => 'post',
                                        -action => "http://$servername/$scriptname"
                ),
                $viralator->hidden(
                                    -name    => 'action',
                                    -default => 'popup'
                ),

                $viralator->hidden(
                                    -name    => 'filename',
                                    -default => $filename
                ),

                $viralator->hidden(
                                    -name    => 'fileurl',
                                    -default => $fileurl
                ),

                $viralator->hidden(
                                    -name    => 'temp_dir',
                                    -default => $temp_dir
                ),

                $viralator->hidden(
                                    -name    => 'digest',
                                    -default => $digest
                ),

                $viralator->p(
                               $lang{wusername},
                               ':',
                               $viralator->textfield( -name => 'username' ),
                               $viralator->start_br(),
                               $lang{wpassword},
                               ':',
                               $viralator->password_field( -name => 'password' )
                ),

                $viralator->p( { -align => 'center' },
                               $viralator->submit( -name => $lang{tryagain} ) ),

                $viralator->end_form;

            return (2);

        } else {

            $username = clean_taint( $username, '\w\-\_' );
            $password = clean_taint( $password, '\w\-\_\.\?\!\@\#\$\%\&' );

            # constructing 'netloc'
            my $pos = index( $fileurl, '//' ) + 2;
            my $lk = substr( $fileurl, $pos, index( $fileurl, '/', $pos ) - $pos );
            my $lk1 = $response->header('Client-Peer');
            $pos = index( $lk1, ':' );
            $lk1 = substr( $lk1, $pos + 1 );
            $lk .= ":$lk1";

            # extracting realm name
            $lk1 = $response->header('WWW-Authenticate');
            $pos = index( $lk1, '"' );
            $lk1 = substr( $lk1, $pos + 1, index( $lk1, '"', $pos + 1 ) );
            $lk1 =~ s/^\"//;
            $lk1 =~ s/\"$//;

            $fetcher->credentials( $lk, $lk1, $username, $password );

            # trying again
            $response = $fetcher->head($fileurl);

        }

    }

RESPONSE: {

        if ( $response->is_success ) {

            my $filetype = $response->content_type;
            my $filesize = $response->content_length;
            $bar_value = $filesize / 50;
            $filesize  = fbytes($filesize);

            #changing value of the parameter 'action'
            #the value 'popup' sticks on it

            $viralator->param( -name  => 'action',
                               -value => 'StopMe' );

            # "One print to rule them all"
            print $viralator->start_form(
                                          -method => 'post',
                                          -action => $scriptname
                ),

                $viralator->hidden(
                                    -name    => 'action',
                                    -default => 'StopMe'
                ),

                $viralator->hidden(
                                    -name    => 'filename',
                                    -default => $filename
                ),

                $viralator->hidden(
                                    -name    => 'temp_dir',
                                    -default => $temp_dir
                ),

                # this parameter will be necessary so Viralator download can be canceled
                $viralator->hidden(
                                    -name    => 'processid',
                                    -default => $$
                ),

                $viralator->hidden(
                             -name    => 'digest',
                             -default => md5_base64( $filename, $$, $config{secret}, $temp_dir )
                ),

                $viralator->start_h3, $viralator->submit( -name => $lang{stop} ),
                $viralator->end_h3,   $viralator->endform,

                # this table will show the requested download information
                #
                $viralator->table(
                                   { -class => 'download-info' },
                                   $viralator->Tr(
                                                   [
                                                     $viralator->td(
                                                          { -class => 'download-info-cell' },
                                                          [ $lang{filetype}, $filetype ]
                                                     ),
                                                     $viralator->td(
                                                          { -class => 'download-info-cell' },
                                                          [ $lang{filesize}, $filesize ]
                                                     )
                                                   ]
                                   )
                ),

                # progress bar
                $viralator->p( $lang{progress} ), $config{progress_indicator},
                $viralator->start_br();

            # secure file concurrency procedures
            # :TODO:24/01/2006:ARFJr: should use sysopen function to avoid race conditions

            open( FILE, ">$config{downloads}/$temp_dir/$filename" )
                or error2(
                           [
                             'error',
                             "$lang{download_error} $lang{admincall}",
                             "Cannot create $filename: $!",
                             'noheader', $config{downloads}, $temp_dir, $filename
                           ]
                );

            $response = $fetcher->get( $fileurl, ':content_cb' => \&callback );
            my $result = ( $response->is_success ) ? 1 : 0;
            close(FILE);

            # change mod to ensure the file can be read
            $config{filechmod} = clean_taint( $config{filechmod}, '\d' );

            chmod( oct( $config{filechmod} ), "$config{downloads}/$temp_dir/$filename" )
                or error2(
                           [
                             'error', $lang{filenotfound},
                             "Cannot chmod $config{downloads}/$temp_dir/$filename: $!",
                             'noheader', $config{downloads}, $temp_dir, $filename
                           ]
                );

            if ( $count_bar < 50 ) {

                my $buffer;

                while ( $count_bar < 50 ) {

                    $buffer .= $config{progress_unit};
                    $count_bar++;

                }

                # this prints the end of progress bar
                print $buffer, $viralator->p( $lang{finished} ), $viralator->hr;

            } else {

                print $viralator->p( $lang{finished} ), $viralator->hr;

            }

            return ($result);
            last RESPONSE;

        }

        if ( $response->status_line =~ /404 Not Found/ ) {

            error( 'warn', $lang{filenotfound}, $response->status_line, 'noheader' );

            return 0;

            last RESPONSE;

        }

        if ( $response->status_line =~ /Host not found/ ) {

            error( 'warn', $lang{hostnotfound}, $response->status_line, 'noheader' );

            return 0;
            last RESPONSE;

        }

        if ( $response->status_line =~ /401 Authorization Required/ ) {

            print $viralator->h3( $lang{error} ), $viralator->p( $lang{autherr} ),
                $viralator->p(
                 $lang{totry},
                 $viralator->a(
                     { -href => "http://$servername$scriptname?action=popup&fileurl=$fileurl" },
                     $lang{here}
                 )
                );

            return 0;
            last RESPONSE;

        } else {

            error(
                   'warning',
                   "$lang{download_error} $lang{admincall}",
                   'Undefined error :' . $response->status_line,
                   'noheader'
            );

            return 0;
            last RESPONSE;

        }

        #end of RESPONSE block
    }

    #end of function
}

#antivirus calling to clean downloaded file

sub cleanit {

    my $fileurl  = shift;
    my $filename = shift;
    my $temp_dir = shift;

    # untaint data
    $config{scannerpath}  = clean_taint( $config{scannerpath},  @{ [UNIX_DIR_REGEX] } );
    $config{virusscanner} = clean_taint( $config{virusscanner}, '\w' );

    $config{viruscmd} = clean_taint( $config{viruscmd}, '\w\.\,\'\_\-\s' );
    $config{downloads} = clean_taint( $config{downloads}, @{ [UNIX_DIR_REGEX] } );
    $filename = clean_taint( $filename, @{ [FILE_REGEX] } );
    $temp_dir = clean_taint( $temp_dir, @{ [UNIX_DIR_REGEX] } );

    # putting the parameters to an array, as expected by IPC::Open3
    my @viruscmd = split( /\s/, $config{viruscmd} );

    delete @ENV{qw(IFS CDPATH ENV BASH_ENV PATH)};
    $ENV{PATH} = $config{scannerpath};

    $| = 1;

    print $viralator->p( $lang{wviruscan}, $filename, $lang{takeawhile} );

    if ( -e "$config{downloads}/$temp_dir/$filename" ) {

        my $pid =
            open3( \*TOCHILD, \*CMD_OUT, \*CMD_ERR,
                   "$config{scannerpath}/$config{virusscanner}",
                   @viruscmd, "$config{downloads}/$temp_dir/$filename" );

        close(TOCHILD)
            or error2(
                       [
                         'error',
                         "$lang{download_error} $lang{admincall}",
                         'Could not close TOCHILD pipe',
                         'noheader', $config{downloads}, $temp_dir, $filename
                       ]
            );

        my $kid;

        do {

            $kid = waitpid( $pid, WNOHANG );

        } until ( $kid == $pid );

        my $selector = IO::Select->new();
        $selector->add( *CMD_ERR, *CMD_OUT );

        my @ready;

        unless ( defined($pid) ) {

            error2(
                    [
                      'error',
                      "$lang{download_error} $lang{admincall}",
                      "Cannot fork viruscanner: $!",
                      'noheader', $config{downloads}, $temp_dir, $filename
                    ]
            );

        } else {

            print $viralator->start_div( { -class => 'scanner' } );

            while ( @ready = $selector->can_read() ) {

                foreach my $fh (@ready) {

                    # all error messages should go to log file, never user's window

                    if ( fileno($fh) == fileno(CMD_OUT) ) {

                        while (<CMD_OUT>) {

                            error2(
                                    [
                                      'error',
                                      $lang{download_error},
                                      'Viruscan error: caught open3 exception.',
                                      'noheader',
                                      $config{downloads},
                                      $temp_dir,
                                      $filename
                                    ]
                                )
                                if ( $_ =~ /^open3\:.*failed/ );

                            if ( $_ =~ /$config{alert}/o ) {

                                # putting the scanner message in the log file
                                warn $_;

                                error2(
                                        [
                                          'warning',
                                          "$lang{vfounddl}: $lang{fileremoved}.",
                                          "Virus found in file $filename",
                                          'noheader',
                                          $config{downloads},
                                          $temp_dir,
                                          $filename
                                        ]
                                );

                            } else {

                                # print viruscanner information about the file scanned
                                if ( $config{scannersummary} eq 'true' ) {

                                    if (     ( $config{skip_downloads} eq 'true' )
                                         and (/$config{downloads}/o) )
                                    {

                                        next;

                                    } else {

                                        print $_, $viralator->start_br();

                                    }

                                } else {

                                    print '.';

                                }

                            }

                            # end of CMD_OUT
                        }

                    } else {

                        # error messages from viruscanner goes to log file
                        while (<CMD_ERR>) {

                            warn $_;

                        }

                    }

                    $selector->remove($fh) if eof($fh);

                }

            }

            print $viralator->end_div();

            #end of if block
        }

        close(CMD_ERR)
            or error2(
                       [
                         'error', $lang{download_error}, 'Could not close CMD_ERR child pipe',
                         'noheader', $config{downloads}, $temp_dir, $filename
                       ]
            );

        close(CMD_OUT)
            or error2(
                       [
                         'error', $lang{download_error}, 'Could not close CMD_OUT child pipe',
                         'noheader', $config{downloads}, $temp_dir, $filename
                       ]
            );

        # test for child returning code and decide if aborts everything

        error2(
                [
                  'error', $lang{download_error},
                  "Error with child process ended download operation: $?",
                  'noheader', $config{downloads}, $temp_dir, $filename
                ]
            )
            unless ( $? == 0 );

    } else {

        error( 'warning', $lang{no_resource},
               "File $config{downloads}/$temp_dir/$filename does not exists", 'noheader' );

        #end of if block
    }

    print $viralator->start_br(), $viralator->start_br(),
        $viralator->hr( { align => 'center' } ), window_scrolldown();

}

# tests the download repository

sub test_repository {

    my $dir = shift;
    opendir( DIR, $config{downloads} )
        or error( 'error', $lang{repository}, "Cannot open $config{downloads}: $!" );
    close(DIR);

}

# parses the filename from the url

sub parse_fileurl {

    my $fileurl = shift;
    my $position;
    my @temp;

    # cuts http:// and similar stuff

    $fileurl =~ s/^[hf]t+ps?\:\/\///;

    error( 'warning', $lang{urlerr}, $lang{urlerr} ) if ( $fileurl eq '' );

    # this puts the fileurl into an array
    @temp     = split( /\//, $fileurl );
    $position = @temp - 1;

    my $filename = splice( @temp, $position );
    $filename = clean_taint( $filename, @{ [FILE_REGEX] } );

    return $filename;

}

# test if the parameter has a value
# $object is the object being treated, the variable name without "$"
# $param is the variable itself, with it's value
sub test_param {

    my $object = shift;
    my $param  = shift;

    error( 'error', "$object: $lang{missing_parameter}", "$object: $lang{missing_parameter}" )
        if ( $param eq '' or ( !defined($param) ) );

}

sub clean_taint {

    my $word    = shift;
    my $pattern = shift;

    if ( $word =~ /(^[$pattern]+$)/ ) {

        return ($1);

    } else {

        error( 'warning', $lang{download_error}, "$lang{invalid_char} $word" );
    }

}

sub callback {

    my ( $data, $response, $protocol ) = @_;

    $datasum += length($data);

    my $total_printed = $bar_value * $count_bar;

    if ( ( $datasum >= $total_printed ) and ( $count_bar < 50 ) ) {

        print $config{progress_unit};
        $count_bar++;

    }

    print FILE $data;

}

#function borrowed from lwp-download,v 2.1 2002/01/03 02:09:24 gisl

sub fbytes {

    my $n = int(shift);

    if ( $n >= 1024 * 1024 ) {

        return sprintf "%.3g MB", $n / ( 1024.0 * 1024 );

    } elsif ( $n >= 1024 ) {

        return sprintf "%.3g KB", $n / 1024.0;

    } else {

        return "$n bytes";

    }
}

# to be called when the script receives a kill sign
sub terminated {

    my $date = localtime(time);
    die "[$date] warning: request process killed by $client\n";

}

# prints the Javascript function WinOpen in to the HTML code
sub WinOpen {

    my $url             = shift;
    my $random_number   = shift;
    my $window_property = shift;

    print <<BLOCK;
<SCRIPT LANGUAGE="JAVASCRIPT">
<!--
function WinOpen() {

    open("$url","$random_number","$window_property");
    
} 
//-->
</SCRIPT>
BLOCK

}

sub rm_download {

    # dir is $config{download}/$temp_dir

    my $dir  = shift;
    my $file = shift;

    $dir = clean_taint( $dir, @{ [UNIX_DIR_REGEX] } );

    unlink "$dir/$file"
        or error( 'error', "$lang{download_error}",
                  "Error when trying to remove download file $file: $!", 'noheader' );

    rmdir $dir
        or
        error( 'error', $lang{rm_error}, "Error when trying to remove $dir: $!", 'noheader' );

}

# extends the error function removing the download and
# temp directory
sub error2 {

    # array ref (from a anonymous array) with the following content
    # 0 - type of error
    # 1 - user error message
    # 2 - log error message
    # 3 - HTML header flag
    # 4 - $config{downloads}
    # 5 - $temp_dir
    # 6 - $filename

    my $args = shift;

    rm_download( "$args->[4]/$args->[5]", $args->[6] );

    error( $args->[0], $args->[1], $args->[2], $args->[3] );

}

# prints Javascript code to scroll down the window to show the last messages
sub window_scrolldown {

    # thanks to Guillaume Girard (cyberoux@wanadoo.fr) for the tip

    return $viralator->script( { -language => 'Javascript' }, 'checkPageBase();' );

}

# prints the Javascript code used by Viralator
sub set_javascript {

    # check if we should make the browser goes back when the download window opens
    my $popback = shift;

    print <<BLOCK;
<SCRIPT LANGUAGE="JavaScript">
<!--
function checkPageBase() {
    window.scrollBy(0,1000);
}
var intervalID1 = setInterval("checkPageBase()",10);
$popback
//-->
</script>
BLOCK

}

# Compare a given digest with a calculated one using the given strings
# Returns true if the given and calculated digest are equal
sub compare_digests {

    my $given_digest = shift;
    my $calculated   = md5_base64(@_);

    ( $given_digest eq $calculated ) ? return 1 : return 0;

}    # ----------  end of subroutine compare_digests  ----------

# :WARNING:24/01/2006:ARFJr: This function's a terrible hack! It should be
# using OOP inheritante and method overloading
# This will check for the existence of -lang and -encoding (actually HTTP
# charset parameter since it's the same value, but in the HTML header) and
# prints a HTML header with those values
sub html_start {

    # hash reference
    my $params_ref = shift;
    my %header_params = (
                         -site    => SITE,
                         -BGCOLOR => BGCOLOR,
                         -style => { -src => 'http://' . $servername . '/' . $config{css_file} }
    );

    if ( exists( $params_ref->{title} ) ) {

        $header_params{'-title'} = $params_ref->{title};

    } else {

        $header_params{'-title'} = VERSION_TITLE . VERSION_NUMBER,

    }

    $header_params{'-onload'} = $params_ref->{onload}
        if ( exists( $params_ref->{onload} ) );

    if ( ( exists( $config{lang} ) ) and ( defined( $config{lang} ) ) ) {

        $header_params{'-lang'}     = $config{lang};
        $header_params{'-encoding'} = $config{charset};

    }

    # :WARNING:02/02/2006:ARFJr: this forces CGI.pm not using XML declaration due a bug with FTP redirection and IE6+
    $header_params{'-declare_xml'} = 0;

    return $viralator->start_html( \%header_params );

}
