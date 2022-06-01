
const TARGET_RASP_LIB = "libRASP.so";
const TARGET_RASP_LIB_REGEXP = /libRASP\.so$/;

// Second step : profiling lib
Interruptor.newAgentTracer({
    followThread: false,
    exclude: {
        syscalls:[/gettime/,/linkat/,/madvise/,/mprotect/]
    },
    output: {
        tid: true,
        inst: false,
        module: true
    },
    svc:{
        read: {
            onEnter: function(ctx){
                const f = ctx.dxcFD[ctx.x0.toInt32()];

                if( f != null){
                    if( /^\/proc\/.+\/maps$/g.exec(f)){
                        ctx.maps = true;
                    }
                    else if(f!=null && f.indexOf("selinux/enforce")>-1){
                        ctx.selinux = true;
                    }
                    else if(f!=null && f.indexOf("/mounts")>0){
                        ctx.mounts = true;
                    }
                }
            },
            onLeave: function(ctx){

                if(ctx.maps){
                    ctx.maps = false;

                    let res = null;
                    res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), RWX_PATTERN);
                    if(res.length > 0){
                        res.map( m => m.address.writeByteArray([0x72,0x2D,0x78]));
                        console.warn("replace 'rwx' by 'r-x' from resulting buffer");
                    }

                    //res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), FRIDA_PATTERN);

                    res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), FRIDA_PATTERN);
                    if(res.length > 0){
                        // res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41]));


                        let res1 = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), FRIDA_AGENT_PATTERN);
                        if(res1.length > 0){
                            res1.map( m => m.address.writeByteArray(
                                Interruptor.utils().toByteArray('/system/lib64/frida-agent.so', FRIDA_AGENT_PATH.length, 0x20)
                            ));
                            console.warn( "remove 'frida' pattern from resulting buffer");
                        }else{

                            res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41]));
                            console.warn("remove 'frida' pattern from resulting buffer");
                        }


                        return ;
                    }

                    res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), LIBC_PATTERN);
                    if(res.length > 0){
                        res.map( m => m.address.writeByteArray([0x6c,0x69,0x62,0x71,0x2E]));
                        console.warn("replace 'libc.' by 'libz.' pattern from resulting buffer");
                        return ;
                    }



                    res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), LINKER_PATTERN);
                    /*
                    75ccf1a000-75cd041000 r-xp 00000000 103:16 2175                          /system/bin/linker64
                    75cd05e000-75cd06a000 r--p 00134000 103:16 2175                          /system/bin/linker64
                    75cd06a000-75cd06b000 rw-p 00140000 103:16 2175                          /system/bin/linker64
                     */
                    // replace [anon:linker_alloc]\x00
                    if(false){ //res.length > 0){

                        if(PATCH_NEXT_READ){
                            let buffer = ctx.x1.readCString();
                            const p = buffer.indexOf('/system/bin/linker64');
                            if(p>-1){
                                ctx.x1.add(p).writeU8('['.charCodeAt(0));
                                PATCH_NEXT_READ = false;
                            }
                        }

                        let res2 = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPattern("-xp"));
                        if(res2.length > 0){
                            let buffer = ctx.x1.readCString();
                            console.log(ctx.x1.readCString());

                            res2.map( match => {
                                let rel = -1;
                                let size = match.address.add(4).readCString(8);
                                let pos = -1;
                                if(["00000000","00134000","00140000"].indexOf(size)==-1){

                                    console.warn("replace '/system/bin/linker64' by '[anon:linker_alloc]0x00' pattern from resulting buffer");

                                    // search offset of the size of region relative to x1
                                    rel = match.address.add(4).sub(ctx.x1);

                                    //console.log(rel, buffer.indexOf('/system/bin/linker64', rel.toUInt32()) );

                                    pos = buffer.indexOf('/system/bin/linker64', rel.toUInt32());
                                    if(pos > -1){
                                        match.address.add(pos).writeU8('['.charCodeAt(0));
                                        //.writeByteArray(Interruptor.utils().toByteArray("[anon:linker_alloc]",LINKER_PATTERN.length, 0x20 ));
                                    }else{
                                        PATCH_NEXT_READ = true;
                                    }


                                    // if size is not followed by /system/bin/linker64', next read() must be patched

                                    // else
                                    // console.log(ctx.x1.readCString());
                                    //console.log("Invalid linker size :"+size);
                                    //match.address
                                    //    .add("00000000 103:16 2175                          ".length)
                                    //    .writeByteArray(Interruptor.utils().toByteArray("[anon:linker_alloc]",LINKER_PATTERN.length, 0x20 ));
                                    //console.warn("replace '/system/bin/linker64' by '[anon:linker_alloc]0x00' pattern from resulting buffer");
                                    //console.log(ctx.x1.readCString());
                                    return; ;
                                }
                            });
                        }
                    }else if(PATCH_NEXT_READ){
                        let buffer = ctx.x1.readCString();
                        const p = buffer.indexOf('/system/bin/linker64');
                        if(p>-1){
                            ctx.x1.add(p).writeU8('['.charCodeAt(0));
                            PATCH_NEXT_READ = false;
                        }
                    }
                }

                else if(ctx.mounts){
                    res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), MAGISK_PATTERN);
                    if(res.length > 0){
                        res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41,0x41]));
                        console.warn("replace 'magisk' by 'AAAAAA' pattern from resulting buffer");
                        return ;
                    }
                }

                if(ctx.selinux){
                    console.log("/sys/fs/selinux/enforce  : "+ctx.x1.readInt());
                    ctx.x1.writeByteArray([0x31]);
                    ctx.selinux = false;
                    return;
                }
                /*res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPattern('tmp'));
                if(res.length > 0){
                    res.map( m => m.address.writeByteArray([0x41,0x41,0x41]));
                    console.warn("remove 'tmp' pattern from resulting buffer");
                }
                res = Memory.scanSync(ctx.x1, ctx.x2.toInt32(), Interruptor.utils().toScanPattern('magisk'));
                if(res.length > 0){
                    res.map( m => m.address.writeByteArray([0x41,0x41,0x41,0x41,0x41,0x41]));
                    console.warn("remove 'magisk' pattern from resulting buffer");
                }*/
            }
        }
    },
    onStart: function( path, cfg){
        const libc = Process.findModuleByName('libc.so');
        let libdexA = null;
        const libdl = Process.findModuleByName('libdl.so');




        Interceptor.attach(libdl.findExportByName("dlsym"), {
            onEnter: function(args){
                console.error("[HOOK][libdl.so]["+this.context.pc+"]  dlsym("+args[0]+"): ");
            }
        });

        Interceptor.attach(libdl.findExportByName("dlopen"), {
            onEnter: function(args){
                this.path = args[0].readCString();
                this.mode = args[1].toUInt32();
                //console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
            },
            onLeave: function(ret){

                console.error("[HOOK][libdl.so]["+this.context.pc+"]  dlopen("+this.path+", "+this.mode+"): "+ret);
            }
        });
        Interceptor.attach(libdl.findExportByName("dladdr"), {
            onEnter: function(args){
                this.addr = args[0];
                this.info = args[1];

                /*if(args[1].readPointer().readCString().indexOf('frida')>-1){
                    console.warn("dladdr ....")
                   // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
                }*/
                //console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
            },
            onLeave: function(args){
                const m = Process.findModuleByAddress(this.addr);
                const r = Process.findRangeByAddress(this.addr);
                console.log(JSON.stringify(m));
                console.log(JSON.stringify(r));



                console.error("[HOOK][libdl.so]["+this.context.pc+"]  dladdr("+this.addr+"): \n"+
                    `\tfname = ${this.info.readPointer().readCString()}\n\tfbase = ${this.info.add(8).toUInt32()}\n\tsname = ${this.info.add(16).readPointer().readCString()}\n\tsaddr = ${this.info.add(24)} `
                );

                /*Process.enumerateRanges('rwx').map( x => {
                   if(x.file != null && x.file.path != null && x.file.path.indexOf('libc.so')>-1){
                       console.log()
                   }
                });*/


            }
        });

        Interceptor.attach(libc.findExportByName("__system_property_get"), {
            onEnter: function(args){
                console.error("[HOOK][libc.so]["+this.context.pc+"]  __system_property_get : "+args[0].readCString());
            }
        });
        Interceptor.attach(libc.findExportByName("execv"), {
            onEnter: function(args){
                console.error("[HOOK][libc.so]["+this.context.pc+"]  execv ("+args[0].readCString()+", "+args[0].readCString()+")");
            }
        });
        Interceptor.attach(libc.findExportByName("__system_property_read"), {
            onEnter: function(args){
                console.error("[HOOK][libc.so]["+this.context.pc+"]  __system_property_read : "+args[0].readCString());
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
            }
        });



        libdexA = Process.findModuleByName(TARGET_RASP_LIB);
        Interceptor.attach(libdexA.base.add(0x8b10), {
            onEnter: function(args){
                //this.current_region = args[1];
                console.log(hexdump(args[0], {length:6*10}));

                if(args[0].toUInt32()>0){
                    args[0].add(6*8).writeULong(0);
                    console.log(hexdump(args[0], {length:16*5}));
                }

            },
            onLeave: function(ret){
                console.log(`\x1b[92m [HOOK] scan_bin_content FIX (): ${ret} \x1b[0m`);
                //this.current_region.add(40).writePointer(0); //.add(40).writeU32(0);
            }
        });




    }
}).startOnLoad(TARGET_RASP_LIB_REGEXP,{});