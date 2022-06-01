const APP_PKG_NAME = "XXX.YYY.ZZZ";

// Android <= 9 + spawn + pause
Java.performNow( ()=>{

    const JFile = Java.use('java.io.File');
    const JDexFile = Java.use('dalvik.system.DexFile');
    const JFileOuputStream = Java.use("java.io.FileOutputStream");

    const JDexCookie = JDexFile.createCookieWithArray.overload('[B','int','int');
    JDexCookie.implementation = function(byteArr, start, end){


        // to prevent out of memory issue, byte array is wrote into application folder
        // by the application itself

        const d = '/data/data/'+APP_PKG_NAME;
        let p = 'inmemory_'+end+'_'+Date.now()+'.dex';

        let f = JFile.$new(d, p);
        let fos = JFileOuputStream.$new(f);
        fos.write(byteArr);
        fos.close();

        send({ app_path: d+"/"+p });

        console.log("\x1b[91mDexFile : createCookie : loading "+(end-start)+" bytes. \x1b[0m");
        return JDexCookie.call(this, byteArr, start, end);
    }

    console.log("Hooks loaded :) ");
});