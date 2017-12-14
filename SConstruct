# 
# libsse_crypto - An abstraction layer for high level cryptographic features.
# Copyright (C) 2015-2017 Raphael Bost
# 
# This file is part of libsse_crypto.
# 
# libsse_crypto is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# libsse_crypto is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with libsse_crypto.  If not, see <http://www.gnu.org/licenses/>.
# 


import os, sys


def smart_concat(l1, l2):
    if l1 == None:
        return l2
    elif l2 == None:
        return l1
    else:
        return l1 + l2

def print_cmd_line(s, targets, sources, env):
    """s       is the original command line string
       targets is the list of target nodes
       sources is the list of source nodes
       env     is the environment"""
    cmd = s.split(' ', 1)[0]
    in_str = "%s "% (' and '.join([str(x) for x in sources]))
    out_str = "=> %s\n"% (' and '.join([str(x) for x in targets]))
    sys.stdout.write(cmd + "\t " + in_str + " " + out_str)


def run_test(target, source, env):
    app = str(source[0].abspath)
    if os.spawnl(os.P_WAIT, app, app)==0:
        return 0
    else:
        return 1

bld = Builder(action = run_test)

## Environment initialization and configuration

env = Environment(tools = ['default', 'gcccov', 'doxygen'])
env['PRINT_CMD_LINE_FUNC'] = print_cmd_line
env.Append(BUILDERS = {'Test' :  bld})
env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1

try:
    # env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
    env.Append(ENV = os.environ) # Keep our nice terminal environment (like colors ...)
except:
    print("Not running in a terminal")


if 'CC' in os.environ:
    env['CC']=os.environ['CC']
    
if 'CXX' in os.environ:
    env['CXX']=os.environ['CXX']

env.GCovInjectObjectEmitters()

env.Append(CFLAGS=['-std=c99'])
env.Append(CCFLAGS=['-march=native', '-fPIC'])
env.Append(CXXFLAGS=['-std=c++14'])

# C(XX) warnings flags
env.Append(CCFLAGS=['-Wall', '-Wcast-qual', '-Wdisabled-optimization', '-Wformat=2', '-Wmissing-declarations', '-Wmissing-include-dirs', '-Wredundant-decls', '-Wshadow', '-Wstrict-overflow=5', '-Wdeprecated', '-Wno-unused-function'])
env.Append(CXXFLAGS=['-Weffc++', '-Wnon-virtual-dtor','-Woverloaded-virtual',  '-Wsign-promo', '-Wstrict-overflow=5'])


if env['PLATFORM'] == 'darwin':
    # Add the OpenSSL include path from Homebrew
    env.Append(CPPPATH=['/usr/local/opt/openssl/include'])
    env.Append(LIBPATH=['/usr/local/opt/openssl/lib'])


env.Append(LIBS = ['gmp','sodium'])


## Load the configuration file

if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='env')



def CheckFSanUseAfterScope(context):
    context.Message( 'Checking for -fsanitize-address-use-after-scope flag ...' )
    lastCCFLAGS = context.env['CCFLAGS']
    lastLINKFLAGS = context.env['LINKFLAGS']
    context.env.Append(CCFLAGS = '-fsanitize-address-use-after-scope' )
    context.env.Append(LINKFLAGS = '-fsanitize-address-use-after-scope' )
    ret = context.TryCompile("""
int main(int argc, char **argv) {
  return 0;
}
""", '.c')
    context.env.Replace(CCFLAGS = lastCCFLAGS, LINKFLAGS=lastLINKFLAGS)
    context.Result( ret )
    return ret

# Look for the configuration of the machine
conf = Configure( env, custom_tests = { 'CheckFSanUseAfterScope' : CheckFSanUseAfterScope } )

conf.env['HAS_FSanUseAfterScope']=conf.CheckFSanUseAfterScope()

if conf.CheckLib( 'crypto' ):
    conf.env.Append( CPPFLAGS = '-DWITH_OPENSSL' )
    conf.env.Append(LIBS = ['crypto'])
    conf.env['HAS_OPENSSL'] = True
else:
    conf.env['HAS_OPENSSL'] = False

env = conf.Finish()

## Read the arguments passed to the building script

static_relic = ARGUMENTS.get('static_relic', 0) # use the static version of RELIC
if int(static_relic):
    env.Append(LIBS = ['relic_s'])
else:
	env.Append(LIBS = ['relic'])


debug = ARGUMENTS.get('debug', 0) # debug mode

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])

sanitize_address = ARGUMENTS.get('sanitize_address', 0) # debug mode

if int(sanitize_address):
    env.Append(CCFLAGS = ['-fsanitize=address','-fno-omit-frame-pointer'])
    env.Append(LINKFLAGS = ['-fsanitize=address','-fno-omit-frame-pointer'])
    if env['HAS_FSanUseAfterScope']:
        env.Append(CCFLAGS = '-fsanitize-address-use-after-scope' )
        env.Append(LINKFLAGS = '-fsanitize-address-use-after-scope' )
        

sanitize_undefined = ARGUMENTS.get('sanitize_undefined', 0) # debug mode

if int(sanitize_undefined):
    env.Append(CCFLAGS = ['-fsanitize=undefined','-fno-omit-frame-pointer'])
    env.Append(LINKFLAGS = ['-fsanitize=undefined','-fno-omit-frame-pointer'])



coverage = ARGUMENTS.get('coverage', 0) # activate coverage
if int(coverage):
    env.Append(CCFLAGS = ['-fprofile-arcs','-ftest-coverage', '-fno-inline', '-fno-inline-small-functions', '-fno-default-inline','-Wno-ignored-optimization-argument'])
    env.Append(LINKFLAGS = ['-fprofile-arcs','-ftest-coverage', '-fno-inline', '-fno-inline-small-functions', '-fno-default-inline'])


rsa_implementation = ARGUMENTS.get('rsa_impl', 'mbedTLS') # choose the RSA implementation in use
if rsa_implementation.lower() != 'mbedTLS'.lower(): # mbedTLS is used by default
    if rsa_implementation.lower() == 'OpenSSL'.lower():
        if env['HAS_OPENSSL'] == False: # ERROR
            raise UserError('Cannot use the OpenSSL RSA implementation: OpenSSL is not present','','','')
        else:
            print("Build using OpenSSL for the RSA implementation")
            env.Append(CCFLAGS = ['-D','SSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL'])
            


run_check = ARGUMENTS.get('run_check', 1) # disable automatic run of the tests

# If we are building the tests
if 'check' in COMMAND_LINE_TARGETS:
    env.Append(CXXFLAGS=['-D', 'CHECK_TEMPLATE_INSTANTIATION'])





objects = SConscript('src/build.scons', exports=['env','smart_concat'], variant_dir='build', duplicate=0)

Clean(objects, 'build')

debug = env.Program('debug_crypto',['main.cpp'] + objects, CPPPATH = smart_concat(['src'], env.get('CPPPATH')))

Default(debug)

# To build the documentation

doc = env.Doxygen('doc/Doxyfile')


# Specific environments for building the libraries
lib_env = env.Clone()
shared_lib_env = lib_env.Clone() 


if env['PLATFORM'] == 'darwin':
    # We have to add '@rpath' to the library install name
    shared_lib_env.Append(LINKFLAGS = ['-install_name', '@rpath/libsse_crypto.dylib'])    
    
library_build_prefix = 'library'
shared_lib = shared_lib_env.SharedLibrary(library_build_prefix+'/lib/sse_crypto',objects);
static_lib = lib_env.StaticLibrary(library_build_prefix+'/lib/sse_crypto',objects)

headers = Glob('src/*.h') + Glob('src/*.hpp') + ['src/ppke/GMPpke.hpp']
headers_lib = [lib_env.Install(library_build_prefix+'/include/sse/crypto', headers)]

env.Clean(headers_lib,[library_build_prefix+'/include'])

Alias('headers', headers_lib)
Alias('lib', [shared_lib, static_lib] + headers_lib)
Clean('lib', 'library')

# Setup for the testing environment

test_env = env.Clone()
test_env.Append(LIBS = ['pthread']) # Needed by GTest

test_objects = SConscript('tests/build.scons', exports=['test_env','smart_concat'], variant_dir='build_test', duplicate=0)

Clean(test_objects, 'build_test')

gtest_obj = test_env.Object('gtest/gtest-all.cc', CPPPATH=['.'])

test_prog = test_env.Program('check', ['checks.cpp'] + objects + test_objects + gtest_obj)

test_run = test_env.Test('test_run', test_prog)
Depends(test_run, test_prog)

# If the run_check=0 option was passed as argument
if int(run_check):
    test_env.Alias('check', [test_prog, test_run])
else:
    test_env.Alias('check', [test_prog])

test_env.Clean('check', ['check'] + objects)


