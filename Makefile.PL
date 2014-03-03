use ExtUtils::MakeMaker;

WriteMakefile(
  ABSTRACT => "Parse NetApp Weekly Auto Support Files",
  AUTHOR   => 'Phil Pollard <bennie@cpan.org>',
  LICENSE  => 'artistic_2',
  NAME     => 'Parse::NetApp::ASUP',
  VERSION  => '1.15',

  PREREQ_PM => {
          'Digest::MD5' => '2.5',
          'Data::Dumper' => 0,
          'Test' => 0,
          'Test::Simple' => 0,
          'File::Slurp' => '9999.19',
          'Carp' => 0
        },

  ( $ExtUtils::MakeMaker::VERSION < 6.46
        ? ()
        : ( META_MERGE => {
                'meta-spec' => { version => 2 },
                no_index => {directory => [qw/t/]},
                provides => {
                     'Parse::NetApp::ASUP' => {
                          file    => 'lib/Parse/NetApp/ASUP.pm',
                          version => '1.15'
                     }
                },
                release_status => 'stable',
                requires  => {perl => '5.008001'},
                resources => {
                    repository => {
                        type => 'git',
                        url  => 'git://github.com/bennie/perl-Parse-NetApp-ASUP.git',
                        web  => 'http://github.com/bennie/perl-Parse-NetApp-ASUP',
                    },
                    bugtracker => {
                        web => 'https://rt.cpan.org/Dist/Display.html?Name=Parse-NetApp-ASUP',
                    },

                },
            },
        )
    )

);