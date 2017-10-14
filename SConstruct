import os, sys

env = Environment(tools = ['default', 'gcccov'])

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


if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='env')

def print_cmd_line(s, targets, sources, env):
    """s       is the original command line string
       targets is the list of target nodes
       sources is the list of source nodes
       env     is the environment"""
    cmd = s.split(' ', 1)[0]
    in_str = "%s "% (' and '.join([str(x) for x in sources]))
    out_str = "=> %s\n"% (' and '.join([str(x) for x in targets]))
    sys.stdout.write(cmd + "\t " + in_str + " " + out_str)

env['PRINT_CMD_LINE_FUNC'] = print_cmd_line

env.Append(CFLAGS=['-std=c99'])
env.Append(CCFLAGS=['-march=native', '-fPIC'])
env.Append(CXXFLAGS=['-std=c++14'])

# warnings
env.Append(CCFLAGS=['-Wall', '-Wcast-qual', '-Wdisabled-optimization', '-Wformat=2', '-Wmissing-declarations', '-Wmissing-include-dirs', '-Wredundant-decls', '-Wshadow', '-Wstrict-overflow=5', '-Wdeprecated', '-Wno-unused-function'])
env.Append(CXXFLAGS=['-Weffc++','-Woverloaded-virtual',  '-Wsign-promo', '-Wstrict-overflow=5'])


env.Append(LIBS = ['crypto','gmp'])


static_relic = ARGUMENTS.get('static_relic', 0)
if int(static_relic):
    env.Append(LIBS = ['relic_s'])
else:
	env.Append(LIBS = ['relic'])

env['AS'] = ['yasm']
env.Append(ASFLAGS = ['-D', 'LINUX'])

if env['PLATFORM'] == 'darwin':
    env.Append(ASFLAGS = ['-f', 'macho64'])
    # Add the OpenSSL include path from Homebrew
    env.Append(CPPPATH=['/usr/local/opt/openssl/include'])
    env.Append(LIBPATH=['/usr/local/opt/openssl/lib'])
else:
    env.Append(ASFLAGS = ['-f', 'x64', '-f', 'elf64'])


env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])

gcov = ARGUMENTS.get('gcov', 0)
if int(gcov):
    env.Append(CCFLAGS = ['-fprofile-arcs','-ftest-coverage'])
    env.Append(LINKFLAGS = ['-fprofile-arcs','-ftest-coverage'])


no_aes_ni = ARGUMENTS.get('no_aesni', 0)
if int(no_aes_ni):
    env.Append(CCFLAGS = ['-D', 'NO_AESNI'])


def run_test(target, source, env):
    app = str(source[0].abspath)
    if os.spawnl(os.P_WAIT, app, app)==0:
        return 0
    else:
        return 1

def smart_concat(l1, l2):
    if l1 == None:
        return l2
    elif l2 == None:
        return l1
    else:
        return l1 + l2

bld = Builder(action = run_test)
env.Append(BUILDERS = {'Test' :  bld})

objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)

Clean(objects, 'build')

debug = env.Program('debug_crypto',['main.cpp'] + objects, CPPPATH = smart_concat(['src'], env.get('CPPPATH')))

Default(debug)

lib_env = env.Clone()
shared_lib_env = lib_env.Clone() 


if env['PLATFORM'] == 'darwin':
    # We have to add '@rpath' to the library install name
    shared_lib_env.Append(LINKFLAGS = ['-install_name', '@rpath/libsse_crypto.dylib'])    
    
library_build_prefix = 'library'
shared_lib = shared_lib_env.SharedLibrary(library_build_prefix+'/lib/sse_crypto',objects);
static_lib = lib_env.StaticLibrary(library_build_prefix+'/lib/sse_crypto',objects)

headers = Glob('src/*.h') + Glob('src/*.hpp') + ['src/ppke/GMPpke.h']
headers_lib = [lib_env.Install(library_build_prefix+'/include/sse/crypto', headers)]

env.Clean(headers_lib,[library_build_prefix+'/include'])

Alias('headers', headers_lib)
Alias('lib', [shared_lib, static_lib] + headers_lib)
Clean('lib', 'library')


test_env = env.Clone()
test_env.Append(LIBS = ['pthread'])

test_objects = SConscript('tests/build.scons', exports='test_env', variant_dir='build_test', duplicate=0)

Clean(test_objects, 'build_test')

gtest_obj = test_env.Object('gtest/gtest-all.cc', CPPPATH=['.'])

test_prog = test_env.Program('check', ['checks.cpp'] + objects + test_objects + gtest_obj)

test_run = test_env.Test('test_run', test_prog)
Depends(test_run, test_prog)

run_check = ARGUMENTS.get('run_check', 1)
if int(run_check):
    test_env.Alias('check', [test_prog, test_run])
else:
    test_env.Alias('check', [test_prog])

test_env.Clean('check', ['check'] + objects)


