# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

use ExtUtils::MakeMaker;

use 5.016;

WriteMakefile
 ( NAME     => 'Open-Console-Tasks'
 , VERSION  => '0.02'

 , PREREQ_PM    => { 
	# Common purpose modules
	'Data::Dumper'           => 0,
	'DateTime'               => 1.50,
	'Devel::GlobalDestruction' => 0,
	'List::Util'             => 0,
	'Log::Report'            => 0,
	'Net::DNS'               => 1.44,
	'Net::DNS::SEC'          => 1.23,
	'Net::LibIDN2'           => 0.12,

	# Website and database framwork
	'Mango'                  => 0,
	'Mojolicious'            => 9.35,

	# Required for the Minion task manager
	'Mojolicious::Plugin::Minion'        => 0,
	'Mojolicious::Plugin::Minion::Admin' => 0,
	'Mojolicious::Plugin::Minion::Workers' => 0.9095,
	'Minion'                 => 10.28,
#	'Minion::Backend::Pg'    => 0,  # part of Minion, no VERSION
	'Mojo::Pg'               => 0,
   }
 , EXE_FILES    => []
 , AUTHOR       => 'Open Console <team@open-console.eu>'
 , ABSTRACT     => 'Open Console Batch Processing'
 , LICENSE      => 'perl_5'

 , META_MERGE =>
      { 'meta-spec' => { version => 2 }
      , resources  =>
          { repository =>
              { type => 'git'
              , url  => 'https://github.com/Skrodon/open-console-tasks.git'
              , web  => 'https://github.com/Skrodon/open-console-tasks'
              }
          , homepage => 'http://open-console.eu'
          , license  => [ 'http://dev.perl.org/licenses/' ]
          }
      }
 );

### used by oodist during production of distribution
sub MY::postamble { <<'__POSTAMBLE' }

# for DIST
RAWDIR          =
DISTDIR         = /home/markov/shared/perl/public_html/open-console-tasks/source

# for POD
FIRST_YEAR      = 2024
EMAIL           = mark@open-console.eu
EXTENDS         = ../open-console-core
WEBSITE         = http://perl.overmeer.net/open-console

css:
	sass scss/main.scss public/assets/open-console.css
__POSTAMBLE
