use inc::Module::Install;

name     'Catalyst-Authentication-Store-RDBO';
all_from 'lib/Catalyst/Authentication/Store/RDBO.pm';
author   'Dave O'Neill <dmo@dmo.ca>';

build_requires 'Test::More';

auto_install;

WriteAll;

