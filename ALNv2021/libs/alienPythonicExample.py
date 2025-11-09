
def examplePrintTest():
    print("Library Executed..")

__alienProgramLibraries__ = {
    "examplePrintTest":{
        "printTest":lambda: examplePrintTest()
    }
}
__alienProgramData__ = {
    "metadata":{
        "author":"J4ck3LSyN",
        "version":"alpha-0.0.1",
        "title":"alienPythonicExample",
        "description":"A test library for alien."
    },
    "functions":{},
    "classes":{},
    "globals":{},
    "inline":[
        {
            "type":"import",
            "moduleName":"io"
        },
        {
            "type":"call",
            "functionName":"io.print",
            "arguments":[
                {
                    "type":"literal",
                    "value":"* Alien Pythonic Example Was Imported!"
                }
            ]
        },
        {
            "type":"call",
            "functionName":"examplePrintTest.printTest",
            "arguments":[]
        }
    ],
    "importList":[]
}