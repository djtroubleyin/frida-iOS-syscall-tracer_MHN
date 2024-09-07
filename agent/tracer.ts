import { Config } from "./config";
import { log } from "./logger";
import { printSyscall } from "./syscalls";

var threadsFollowed: { [id: ThreadId]: boolean } = {};

Process.setExceptionHandler(function (exp: ExceptionDetails) {
    console.log(`${exp.type} @ ${exp.address}`);

    let backtrace = Thread.backtrace(exp.context, Config.exceptionBacktracerType).map(DebugSymbol.fromAddress);
    for (let i in backtrace)
        console.log(backtrace[i]);

    return false;
});

function isThreadFollowed(threadId: ThreadId) {
    return threadsFollowed[threadId];
}

function followThread(threadId: ThreadId, base:NativePointer) {
    if (isThreadFollowed(threadId))
        return;

    threadsFollowed[threadId] = true;
    log("[+] Following thread " + threadId);

    Stalker.follow(threadId, {
        transform(iterator: StalkerArm64Iterator) {
            let instruction = iterator.next();

            do {
                if (instruction?.mnemonic === "svc") {
                    log((instruction?.address.sub(base))?.toString() + "   " + instruction?.mnemonic + " " + instruction?.opStr)
                    iterator.putCallout(printSyscall);
                    
                } else if(Config.verbose) {
                    // log((instruction?.address.sub(base))?.toString() + "   " + instruction?.mnemonic + " " + instruction?.opStr)
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        },
    });
}

function unfollowThread(threadId: ThreadId) {
    if (!isThreadFollowed(threadId))
        return;

    delete threadsFollowed[threadId];
    log("[+] Unfollowing thread " + threadId);

    Stalker.unfollow(threadId);
    Stalker.garbageCollect();
}

// function stalkThreads() {
//     followThread(Process.getCurrentThreadId());
//     Interceptor.attach(Module.getExportByName(null, "_pthread_start"), {
//         onEnter(args) {
//             if (isThreadFollowed(this.threadId)) {
//                 return;
//             }
//             const functionAddress = args[2];
//             Interceptor.attach(functionAddress, {
//                 onEnter() {
//                     followThread(this.threadId);
//                 },
//                 onLeave() {
//                     unfollowThread(this.threadId);
//                 },
//             });
//         },
//     });
// }

function hook_mod_init_func(addr:NativePointer, targetModule:string){
    Interceptor.attach(addr,{
        onEnter: function(){
            // followThread(Process.getCurrentThreadId());
            var context_ptr = this.context as Arm64CpuContext
            var debugSymbol = DebugSymbol.fromAddress(context_ptr.x1)
            if(debugSymbol.moduleName == targetModule){
                let base = Module.findBaseAddress(targetModule);
                if (base != null)
                {
                    Interceptor.attach(debugSymbol.address,{
                        onEnter: function(){
                            // hook_msHookFunction()
                            console.log("init func = " +  debugSymbol.address + " debugsymbol.name = " + debugSymbol.name)
                            followThread(this.threadId, base as NativePointer);
                        },
                        onLeave: function(){
                            unfollowThread(this.threadId);
                        }
                    })
                }
                
 
            }
             
        },onLeave: function(){
 
        }
    })
}
function findSymbolsAndHook(targetModule:string){
    // frida hook dyld
    let dyld =  Process.getModuleByName('dyld');
    if(dyld){
        let symbols = dyld.enumerateSymbols()
        if(symbols){
            symbols.forEach((symbol) => {
                if (symbol.name.indexOf('ImageLoader') >= 0 && symbol.name.indexOf('containsAddress') >= 0){
                    console.log(`symbol name  = ${symbol.name} `)
                    console.log("${symbol.address} = " + symbol.address)
                    hook_mod_init_func(symbol.address,targetModule)
                }
            })
        }
         
    }
 
}
function main(){
    console.log("process id = " + Process.id)
    findSymbolsAndHook("NianticLabsPlugin") // test 替换为自己想要hook的模块名即可。
}

main()

// stalkThreads();
