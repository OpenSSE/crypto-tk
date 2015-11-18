import os

env = Environment()

try:
    env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
except:
    print "Not running in a terminal"


if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='def_env')


env.Append(CCFLAGS=['-Wall', '-march=native'])
env.Append(CXXFLAGS=['-std=c++11'])
env.Append(LIBS = ['crypto']);

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])


objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)
Clean(objects, 'build')
env.Program('test_crypto',['main.cpp'] + objects)