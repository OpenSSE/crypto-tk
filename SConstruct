import os

env = Environment()

try:
    env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
except:
    print "Not running in a terminal"


if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='env')
    
env.Append(CFLAGS=['-std=c99'])
env.Append(CCFLAGS=['-Wall', '-march=native','-fPIC'])
env.Append(CXXFLAGS=['-std=c++14'])
env.Append(LIBS = ['crypto'])

env['AS'] = ['yasm']
env.Append(ASFLAGS = ['-D', 'LINUX'])

if env['PLATFORM'] == 'darwin':
    env.Append(ASFLAGS = ['-f', 'macho64'])
else:
    env.Append(ASFLAGS = ['-f', 'x64', '-f', 'elf64'])


env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])



def run_test(target, source, env):
    app = str(source[0].abspath)
    if os.spawnl(os.P_WAIT, app, app)==0:
        return 0
    else:
        return 1

bld = Builder(action = run_test)
env.Append(BUILDERS = {'Test' :  bld})

objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)
test_objects = SConscript('tests/build.scons', exports='env', variant_dir='build_test', duplicate=0)

Clean(objects, 'build')
Clean(test_objects, 'build_test')

debug = env.Program('debug_crypto',['main.cpp'] + objects, CPPPATH = ['src'])

Default(debug)


shared_lib_env = env.Clone();

if env['PLATFORM'] == 'darwin':
    # We have to add '@rpath' to the library install name
    shared_lib_env.Append(LINKFLAGS = ['-install_name', '@rpath/libsse_crypto.dylib'])
    
library_build_prefix = 'library'
shared_lib = shared_lib_env.SharedLibrary(library_build_prefix+'/lib/sse_crypto',objects);
static_lib = env.StaticLibrary(library_build_prefix+'/lib/sse_crypto',objects)

headers = Glob('src/*.h') + Glob('src/*.hpp') + Glob('src/hash/*.hpp')
hash_headers = Glob('src/hash/*.hpp')
headers_lib = [env.Install(library_build_prefix+'/include/sse/crypto', headers)]
headers_lib += [env.Install(library_build_prefix+'/include/sse/crypto/hash', hash_headers)]

env.Clean(headers_lib,[library_build_prefix+'/include'])

Alias('headers', headers_lib)
Alias('lib', [shared_lib, static_lib] + headers_lib)
# Alias('lib', [lib_install] + headers_lib)



test_env = env.Clone()

if not test_env.GetOption('clean'):
    conf = Configure(test_env)
    if conf.CheckLib('boost_unit_test_framework'):
        print 'Found boost unit test framework'
        
        test_env.Append(LIBS = ['boost_unit_test_framework'])
        
        test_prog = test_env.Program('check', ['checks.cpp'] + objects + test_objects)

        test_run = test_env.Test('test_run', test_prog)
        Depends(test_run, test_prog)

        env.Alias('check', [test_prog, test_run])
        
        # Depends([shared_lib, static_lib, headers_lib], test_run)
        Depends([static_lib, shared_lib, headers_lib], test_run)
        
    else:
        print 'boost unit test framework not found'
        print 'Skipping checks. Be careful!'
    test_env = conf.Finish()





