import codecs
import frida
import sys
import threading


device = frida.get_remote_device()
packetname = 'aaaaa'

pending = []
sessions = []
scripts = []
event = threading.Event()

def on_spawned(spawn):
    print('spawn-added:', spawn)
    pending.append(spawn)
    event.set()

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

device.on('spawn-added', on_spawned)
device.enable_spawn_gating()
event = threading.Event()
print('Enabled spawn gating')
print('Pending:', device.enumerate_pending_spawn())
for spawn in device.enumerate_pending_spawn():
    print('Resuming:', spawn)
    device.resume(spawn.pid)
while True:
    while len(pending) == 0:
        print('Waiting for data')
        event.wait()
        event.clear()
    spawn = pending.pop()
    if spawn.identifier is not None and  spawn.identifier.startswith(packetname):
        print('Instrumenting:', spawn)
        session = device.attach(spawn.pid)
        
        src = """
        var f = Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_7OatFileEPS9_");
        console.log('OpenMemory addr:',f);
        Interceptor.attach(f, {
            onEnter: function (args) {
                console.log('------------------');
                var begin = args[0];
                console.log("magic : ");
                Memory.protect(begin, 4096, 'rwx');
                console.log(Memory.readUtf8String(begin));
             
                var address = parseInt(begin,16) + 0x20;

                var dex_size = Memory.readInt(ptr(address));

                console.log("dex_size :" + dex_size);
                //console.log("------------------------");
                var file = new File("/data/data/%s/" + dex_size + ".dex", "wb");
                file.write(Memory.readByteArray(begin, dex_size));
                file.flush();
                file.close();
            },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
        }
    }
});
""" %('packetname)



        jscode = """
'use strict';
rpc.exports = {        
init: function() {
%s
}   
};
""" % src

        script = session.create_script(jscode)


        script.on('message', on_message)
        script.load()
        script.exports.init()

        sessions.append(session)
        scripts.append(script)
    else:
        print('Not instrumenting:', spawn)
    device.resume(spawn.pid)
    print('Processed:', spawn)
