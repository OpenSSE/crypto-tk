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

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])


objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)
test_objects = SConscript('tests/build.scons', exports='env', variant_dir='build_test', duplicate=0)

Clean(objects, 'build')
Clean(test_objects, 'build_test')

env.Program('debug_crypto',['main.cpp'] + objects)

test_env = env.Clone()
test_env.Append(LIBS = ['boost_unit_test_framework'])

test_env.Program('test_crypto', objects + test_objects)