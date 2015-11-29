import os

env = Environment()

try:
    env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
except:
    print "Not running in a terminal"


if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='env')


env.Append(CCFLAGS=['-Wall', '-march=native'])
env.Append(CXXFLAGS=['-std=c++14'])
env.Append(LIBS = ['crypto'])
env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])


objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)
test_objects = SConscript('tests/build.scons', exports='env', variant_dir='build_test', duplicate=0)

Clean(objects, 'build')
Clean(test_objects, 'build_test')

debug = env.Program('debug_crypto',['main.cpp'] + objects, CPPPATH = ['src'])

Default(debug)

test_env = env.Clone()
test_env.Append(LIBS = ['boost_unit_test_framework'])

test_prog = test_env.Program('check', ['checks.cpp'] + objects + test_objects)



library_build_prefix = 'library'
shared_lib = env.SharedLibrary(library_build_prefix+'/lib/sse_crypto',objects)
static_lib = env.StaticLibrary(library_build_prefix+'/lib/sse_crypto',objects)

headers = Glob('src/*.h') + Glob('src/*.hpp') + Glob('src/hash/*.hpp')
headers_lib = env.Install(library_build_prefix+'/include/sse/crypto', headers)
env.Clean(headers_lib,[library_build_prefix+'/include'])

Alias('headers', [headers_lib])
Alias('lib', [shared_lib, static_lib, headers_lib])

